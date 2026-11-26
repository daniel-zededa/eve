// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package usbmanager

// USB passthrough into native containers (VirtualizationMode NOHYPER).
//
// A VM gets a usb device through QEMU (device_add usb-host). A native
// container shares the host kernel, so it gets the device's nodes instead:
// the usb device node (/dev/bus/usb/BBB/DDD, for libusb) and the nodes of
// the class devices its interface drivers create (/dev/videoN, /dev/ttyACMN,
// /dev/hidrawN, ...), plus the host's udev links to them (/dev/v4l/by-id/...)
// so that applications find them under the same names.
//
// Two things keep a container from using a device it wasn't given at
// create time, and both are done here, while it runs:
//   - the node must exist in its /dev, which is the container's own tmpfs:
//     the nodes are created through /proc/<pid>/root, without following
//     any symlink the container may have put there;
//   - its device cgroup must allow it. With cgroup v2 that is the eBPF
//     program runc attached when it created the container. It is replaced
//     by one built from the rules runc built it from -- the container's OCI
//     spec, read through containerd, plus runc's default devices
//     (runcDefaultDeviceRules) -- and an allow rule per passed-through node,
//     with the code runc uses itself (github.com/opencontainers/cgroups).
//
// On unplug, or when the passthrough goes elsewhere, the nodes and links
// are removed and the program is rebuilt without them.

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup"
	"github.com/opencontainers/cgroups"
	_ "github.com/opencontainers/cgroups/devices" // registers cgroups.DevicesSetV2
	devconfig "github.com/opencontainers/cgroups/devices/config"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

var (
	// loadContainerState finds a running native container through
	// containerd
	loadContainerState = containerdContainerState
	// procRoot and devRoot are where the host's /proc and /dev are
	procRoot = "/proc"
	devRoot  = "/dev"
	// setDeviceFilter replaces the device filter of a cgroup v2 cgroup
	setDeviceFilter = replaceDeviceFilter
	// udevDataDir is udev's database on the host, and udevWait how long to
	// wait for udev to finish with a new node there
	udevDataDir = "/run/udev/data"
	udevWait    = 3 * time.Second
)

// waitForUdev waits, for at most udevWait, until the host's udev has handled
// node n: it records a device in its database at the end of its event, after
// it set the node's mode and owner and added its links. Without this a node
// plugged in while the container runs would get devtmpfs's 0600 root instead
// of udev's mode (e.g. 0660 group video), which a non-root application can't
// open, and its by-id links could be missed. Without udev on the host there
// is nothing to wait for.
func waitForUdev(n devNode) {
	if _, err := os.Stat(udevDataDir); err != nil {
		return
	}
	kind := "c"
	if n.devType == devconfig.BlockDevice {
		kind = "b"
	}
	entry := filepath.Join(udevDataDir, fmt.Sprintf("%s%d:%d", kind, n.major, n.minor))
	deadline := time.Now().Add(udevWait)
	for {
		if _, err := os.Stat(entry); err == nil || time.Now().After(deadline) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// replaceDeviceFilter makes rules the device filter of a cgroup v2 cgroup.
//
// cgroups.DevicesSetV2 attaches the new filter and is meant to replace the
// one already there (BPF_F_REPLACE), but with cilium/ebpf v0.17 the replace
// flag doesn't reach the kernel (link.RawAttachProgram sets only
// replace_bpf_fd), so the old filter stays attached next to the new one.
// The kernel allows a device only if every filter does, so runc's own filter
// would keep denying what the new one allows. Detach all but the newest,
// the one just attached: program IDs only grow.
func replaceDeviceFilter(cgroupDir string, rules []*devconfig.Rule) error {
	if err := cgroups.DevicesSetV2(cgroupDir, &cgroups.Resources{Devices: rules}); err != nil {
		return err
	}

	dir, err := os.Open(cgroupDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	attached, err := link.QueryPrograms(link.QueryOptions{
		Target: int(dir.Fd()),
		Attach: ebpf.AttachCGroupDevice,
	})
	if err != nil {
		return fmt.Errorf("query device filters: %w", err)
	}
	var newest ebpf.ProgramID
	for _, p := range attached.Programs {
		if p.ID > newest {
			newest = p.ID
		}
	}
	for _, p := range attached.Programs {
		if p.ID == newest {
			continue
		}
		prog, err := ebpf.NewProgramFromID(p.ID)
		if err != nil {
			return fmt.Errorf("device filter %d: %w", p.ID, err)
		}
		err = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  int(dir.Fd()),
			Program: prog,
			Attach:  ebpf.AttachCGroupDevice,
		})
		prog.Close()
		if err != nil {
			return fmt.Errorf("detach device filter %d: %w", p.ID, err)
		}
	}
	return nil
}

// linkDirs are the udev directories of persistent links to device nodes,
// relative to /dev; links in them to a passed-through node are recreated in
// the container
var linkDirs = []string{
	"v4l/by-id", "v4l/by-path",
	"serial/by-id", "serial/by-path",
	"input/by-id", "input/by-path",
	"snd/by-id", "snd/by-path",
}

// devNode is a device node, by its name relative to /dev
type devNode struct {
	name         string
	devType      devconfig.Type // devconfig.CharDevice or devconfig.BlockDevice
	major, minor int64
}

// devLink is a symlink relative to /dev and what it points to, relative to
// the link's directory
type devLink struct {
	name   string
	target string
}

// containerDevices is what a usb device has been given to a container as
type containerDevices struct {
	nodes []devNode
	links []devLink
}

// containerState is what passing devices to a running native container
// needs to know about it.
type containerState struct {
	pid       int    // of its init process, whose root is the container's
	cgroupDir string // its cgroup v2 directory
	// rules are the device rules runc built its device cgroup from
	rules []*devconfig.Rule
}

// containerdContainerState asks containerd for a running container's init
// PID and OCI spec. The cgroup directory and the device rules come from the
// spec, which pillar wrote (containerd/oci.go); nothing is read from the
// runtime's own, unversioned state.
func containerdContainerState(containerName string) (containerState, error) {
	var state containerState
	client, err := containerd.NewContainerdClient(false)
	if err != nil {
		return state, err
	}
	defer client.CloseClient()
	ctx, cancel := client.CtrNewUserServicesCtx()
	defer cancel()

	pid, _, status, err := client.CtrContainerInfo(ctx, containerName)
	if err != nil {
		return state, err
	}
	if status != "running" || pid <= 0 {
		return state, fmt.Errorf("container %s is %s", containerName, status)
	}
	ctr, err := client.CtrLoadContainer(ctx, containerName)
	if err != nil {
		return state, err
	}
	spec, err := ctr.Spec(ctx)
	if err != nil {
		return state, fmt.Errorf("OCI spec of %s: %w", containerName, err)
	}
	if spec.Linux == nil || spec.Linux.CgroupsPath == "" {
		return state, fmt.Errorf("OCI spec of %s has no cgroups path", containerName)
	}
	rules, err := specDeviceRules(spec)
	if err != nil {
		return state, fmt.Errorf("OCI spec of %s: %w", containerName, err)
	}
	return containerState{
		pid:       pid,
		cgroupDir: filepath.Join(cgroup.Root, spec.Linux.CgroupsPath),
		rules:     rules,
	}, nil
}

// runcDefaultDeviceRules are the devices runc allows every container on top
// of its OCI spec: AllowedDevices in runc's libcontainer/specconv (runc
// v1.3.3, pkg/runc; unchanged since runc v1.0). They are the device rules a
// container was created with that its spec doesn't hold, so a rebuilt
// filter must have them as well, or the container would lose /dev/null and
// its terminals. Each has the path runc gives it, which matters for
// specDeviceRules.
var runcDefaultDeviceRules = []struct {
	path string
	rule devconfig.Rule
}{
	// mknod of any device; using one still needs an allow rule
	{"", devconfig.Rule{Type: devconfig.CharDevice, Major: devconfig.Wildcard, Minor: devconfig.Wildcard, Permissions: "m", Allow: true}},
	{"", devconfig.Rule{Type: devconfig.BlockDevice, Major: devconfig.Wildcard, Minor: devconfig.Wildcard, Permissions: "m", Allow: true}},
	{"/dev/null", devconfig.Rule{Type: devconfig.CharDevice, Major: 1, Minor: 3, Permissions: "rwm", Allow: true}},
	{"/dev/random", devconfig.Rule{Type: devconfig.CharDevice, Major: 1, Minor: 8, Permissions: "rwm", Allow: true}},
	{"/dev/full", devconfig.Rule{Type: devconfig.CharDevice, Major: 1, Minor: 7, Permissions: "rwm", Allow: true}},
	{"/dev/tty", devconfig.Rule{Type: devconfig.CharDevice, Major: 5, Minor: 0, Permissions: "rwm", Allow: true}},
	{"/dev/zero", devconfig.Rule{Type: devconfig.CharDevice, Major: 1, Minor: 5, Permissions: "rwm", Allow: true}},
	{"/dev/urandom", devconfig.Rule{Type: devconfig.CharDevice, Major: 1, Minor: 9, Permissions: "rwm", Allow: true}},
	// /dev/pts/*
	{"", devconfig.Rule{Type: devconfig.CharDevice, Major: 136, Minor: devconfig.Wildcard, Permissions: "rwm", Allow: true}},
	// /dev/ptmx
	{"", devconfig.Rule{Type: devconfig.CharDevice, Major: 5, Minor: 2, Permissions: "rwm", Allow: true}},
	// tun/tap
	{"", devconfig.Rule{Type: devconfig.CharDevice, Major: 10, Minor: 200, Permissions: "rwm", Allow: true}},
}

// specDeviceRules returns the device rules runc builds a container's device
// cgroup from, as runc's specconv does: the spec's linux.resources.devices
// in order, then runc's defaults, less those whose path the spec has a
// device of its own for.
func specDeviceRules(spec *specs.Spec) ([]*devconfig.Rule, error) {
	var rules []*devconfig.Rule
	if spec.Linux != nil && spec.Linux.Resources != nil {
		for i, d := range spec.Linux.Resources.Devices {
			rule := &devconfig.Rule{Major: devconfig.Wildcard, Minor: devconfig.Wildcard,
				Permissions: devconfig.Permissions(d.Access), Allow: d.Allow}
			switch d.Type {
			case "", "a":
				rule.Type = devconfig.WildcardDevice
			case "b":
				rule.Type = devconfig.BlockDevice
			case "c":
				rule.Type = devconfig.CharDevice
			default:
				return nil, fmt.Errorf("device rule %d: invalid type %q", i, d.Type)
			}
			if d.Access == "" {
				return nil, fmt.Errorf("device rule %d: no access", i)
			}
			if d.Major != nil {
				rule.Major = *d.Major
			}
			if d.Minor != nil {
				rule.Minor = *d.Minor
			}
			rules = append(rules, rule)
		}
	}
	specPaths := make(map[string]bool)
	if spec.Linux != nil {
		for _, d := range spec.Linux.Devices {
			specPaths[d.Path] = true
		}
	}
	for _, def := range runcDefaultDeviceRules {
		if def.path != "" && specPaths[def.path] {
			continue
		}
		rule := def.rule
		rules = append(rules, &rule)
	}
	return rules, nil
}

// readDevNode reads the node a sysfs device has from its uevent file
func readDevNode(ueventPath string) (devNode, bool) {
	f, err := os.Open(ueventPath)
	if err != nil {
		return devNode{}, false
	}
	defer f.Close()

	n := devNode{devType: devconfig.CharDevice}
	var haveMajor, haveMinor bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "MAJOR":
			n.major, err = strconv.ParseInt(value, 10, 64)
			haveMajor = err == nil
		case "MINOR":
			n.minor, err = strconv.ParseInt(value, 10, 64)
			haveMinor = err == nil
		case "DEVNAME":
			n.name = value
		case "DEVTYPE":
			if value == "disk" || value == "partition" {
				n.devType = devconfig.BlockDevice
			}
		}
	}
	if !haveMajor || !haveMinor || n.name == "" || !filepath.IsLocal(n.name) {
		return devNode{}, false
	}
	return n, true
}

// isUSBDeviceDir tells a usb device directory (it has a devnum) from the
// interface and class device directories below a device
func isUSBDeviceDir(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "devnum"))
	return err == nil
}

// usbDeviceNodes returns the nodes of the usb device in sysDir: its own and
// those of the class devices below it, but not those of usb devices behind
// it (a hub's)
func usbDeviceNodes(sysDir string) []devNode {
	var nodes []devNode
	_ = filepath.WalkDir(sysDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// sysfs entries come and go while the device binds
			return nil
		}
		if d.IsDir() {
			if p != sysDir && isUSBDeviceDir(p) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "uevent" {
			return nil
		}
		if n, ok := readDevNode(p); ok {
			nodes = append(nodes, n)
		}
		return nil
	})
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].name < nodes[j].name })
	return nodes
}

// nodeLinks returns the host's udev links to the given nodes
func nodeLinks(nodes []devNode) []devLink {
	byPath := make(map[string]bool)
	for _, n := range nodes {
		byPath[filepath.Join(devRoot, n.name)] = true
	}

	var links []devLink
	for _, dir := range linkDirs {
		entries, err := os.ReadDir(filepath.Join(devRoot, dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.Type()&fs.ModeSymlink == 0 {
				continue
			}
			linkPath := filepath.Join(devRoot, dir, e.Name())
			resolved, err := filepath.EvalSymlinks(linkPath)
			if err != nil || !byPath[resolved] {
				continue
			}
			target, err := filepath.Rel(filepath.Join(devRoot, dir), resolved)
			if err != nil {
				continue
			}
			links = append(links, devLink{name: filepath.Join(dir, e.Name()), target: target})
		}
	}
	return links
}

// openDirInRoot opens dir (relative) below the directory rootFD, creating
// missing directories. No symlink is followed, so a container can't make
// usbmanager create nodes outside of its root.
func openDirInRoot(rootFD int, dir string) (int, error) {
	fd, err := unix.Dup(rootFD)
	if err != nil {
		return -1, err
	}
	for _, comp := range strings.Split(filepath.Clean(dir), "/") {
		if comp == "" || comp == "." {
			continue
		}
		if err := unix.Mkdirat(fd, comp, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
			unix.Close(fd)
			return -1, fmt.Errorf("mkdir %s: %w", comp, err)
		}
		next, err := unix.Openat2(fd, comp, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open %s: %w", comp, err)
		}
		fd = next
	}
	return fd, nil
}

// containerDevDir opens the /dev of the container whose init is pid
func containerDevDir(pid int) (int, error) {
	rootFD, err := unix.Open(filepath.Join(procRoot, strconv.Itoa(pid), "root"),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootFD)
	return openDirInRoot(rootFD, "dev")
}

// createNode creates n below the container's /dev, with the mode and owner
// of the host's node
func createNode(devFD int, n devNode) error {
	dirFD, err := openDirInRoot(devFD, filepath.Dir(n.name))
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	base := filepath.Base(n.name)

	perm, uid, gid := uint32(0o660), 0, 0
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(devRoot, n.name), &st); err == nil {
		perm, uid, gid = st.Mode&0o7777, int(st.Uid), int(st.Gid)
	}
	kind := uint32(unix.S_IFCHR)
	if n.devType == devconfig.BlockDevice {
		kind = unix.S_IFBLK
	}

	_ = unix.Unlinkat(dirFD, base, 0)
	if err := unix.Mknodat(dirFD, base, kind|perm,
		int(unix.Mkdev(uint32(n.major), uint32(n.minor)))); err != nil {
		return fmt.Errorf("mknod %s: %w", n.name, err)
	}
	if err := unix.Fchownat(dirFD, base, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("chown %s: %w", n.name, err)
	}
	// mknod applies the umask
	if err := unix.Fchmodat(dirFD, base, perm, 0); err != nil {
		return fmt.Errorf("chmod %s: %w", n.name, err)
	}
	return nil
}

func createLink(devFD int, l devLink) error {
	dirFD, err := openDirInRoot(devFD, filepath.Dir(l.name))
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	base := filepath.Base(l.name)

	_ = unix.Unlinkat(dirFD, base, 0)
	if err := unix.Symlinkat(l.target, dirFD, base); err != nil {
		return fmt.Errorf("symlink %s: %w", l.name, err)
	}
	return nil
}

// removeEntry removes name (a node or a link) below the container's /dev
func removeEntry(devFD int, name string) {
	dirFD, err := unix.Openat2(devFD, filepath.Dir(name), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return
	}
	defer unix.Close(dirFD)
	_ = unix.Unlinkat(dirFD, filepath.Base(name), 0)
}

// deviceRules returns the device rules a container was created with plus an
// allow rule for each of the nodes
func deviceRules(state containerState, nodes []devNode) []*devconfig.Rule {
	rules := make([]*devconfig.Rule, 0, len(state.rules)+len(nodes))
	rules = append(rules, state.rules...)
	seen := make(map[string]bool)
	for _, n := range nodes {
		rule := &devconfig.Rule{
			Type:        n.devType,
			Major:       n.major,
			Minor:       n.minor,
			Permissions: "rwm",
			Allow:       true,
		}
		if seen[rule.CgroupString()] {
			continue
		}
		seen[rule.CgroupString()] = true
		rules = append(rules, rule)
	}
	return rules
}

// connectUSBDeviceToContainer records, under the controller's lock, that
// the container should have the USB device, and queues it for the worker
// (see containerreconcile.go).
func (uc *usbmanagerController) connectUSBDeviceToContainer(up usbpassthrough) {
	containerName := up.vm.containerName
	if uc.containerWants[containerName] == nil {
		uc.containerWants[containerName] = make(map[string]string)
	}
	uc.containerWants[containerName][up.usbdevice.String()] = filepath.Dir(up.usbdevice.ueventFilePath)
	uc.containerQueue.add(containerName)
}

// disconnectUSBDeviceFromContainer records, under the controller's lock,
// that the container should no longer have the USB device.
func (uc *usbmanagerController) disconnectUSBDeviceFromContainer(up usbpassthrough) {
	containerName := up.vm.containerName
	delete(uc.containerWants[containerName], up.usbdevice.String())
	uc.containerQueue.add(containerName)
}

func containsNode(nodes []devNode, n devNode) bool {
	for _, m := range nodes {
		if m == n {
			return true
		}
	}
	return false
}

func containsLink(links []devLink, l devLink) bool {
	for _, m := range links {
		if m == l {
			return true
		}
	}
	return false
}
