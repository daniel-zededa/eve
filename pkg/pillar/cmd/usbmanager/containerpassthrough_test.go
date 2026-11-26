// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package usbmanager

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	devconfig "github.com/opencontainers/cgroups/devices/config"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeCamera lays out the sysfs of a UVC camera at usb port 1-3: the device
// with its usb node, a video interface with two video4linux nodes, and a
// device behind it (as behind a hub) whose node is not the camera's.
func fakeCamera(t *testing.T) string {
	sys := filepath.Join(t.TempDir(), "1-3")
	writeFile(t, filepath.Join(sys, "devnum"), "5\n")
	writeFile(t, filepath.Join(sys, "uevent"),
		"MAJOR=189\nMINOR=4\nDEVNAME=bus/usb/001/005\nDEVTYPE=usb_device\n")
	writeFile(t, filepath.Join(sys, "1-3:1.0", "uevent"), "DEVTYPE=usb_interface\n")
	writeFile(t, filepath.Join(sys, "1-3:1.0", "video4linux", "video2", "uevent"),
		"MAJOR=81\nMINOR=2\nDEVNAME=video2\n")
	writeFile(t, filepath.Join(sys, "1-3:1.0", "video4linux", "video3", "uevent"),
		"MAJOR=81\nMINOR=3\nDEVNAME=video3\n")
	writeFile(t, filepath.Join(sys, "1-3.1", "devnum"), "6\n")
	writeFile(t, filepath.Join(sys, "1-3.1", "uevent"),
		"MAJOR=189\nMINOR=5\nDEVNAME=bus/usb/001/006\n")
	return sys
}

func TestUSBDeviceNodes(t *testing.T) {
	got := usbDeviceNodes(fakeCamera(t))
	want := []devNode{
		{name: "bus/usb/001/005", devType: devconfig.CharDevice, major: 189, minor: 4},
		{name: "video2", devType: devconfig.CharDevice, major: 81, minor: 2},
		{name: "video3", devType: devconfig.CharDevice, major: 81, minor: 3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nodes %+v, want %+v", got, want)
	}
}

func TestReadDevNodeRejects(t *testing.T) {
	dir := t.TempDir()
	for name, uevent := range map[string]string{
		"no-node":  "DEVTYPE=usb_interface\n",
		"escaping": "MAJOR=81\nMINOR=2\nDEVNAME=../etc/passwd\n",
		"absolute": "MAJOR=81\nMINOR=2\nDEVNAME=/etc/passwd\n",
	} {
		path := filepath.Join(dir, name)
		writeFile(t, path, uevent)
		if n, ok := readDevNode(path); ok {
			t.Errorf("%s: got node %+v", name, n)
		}
	}

	path := filepath.Join(dir, "disk")
	writeFile(t, path, "MAJOR=8\nMINOR=0\nDEVNAME=sda\nDEVTYPE=disk\n")
	if n, ok := readDevNode(path); !ok || n.devType != devconfig.BlockDevice {
		t.Errorf("disk: got %+v %v, want a block device", n, ok)
	}
}

func TestNodeLinks(t *testing.T) {
	oldDevRoot := devRoot
	devRoot = t.TempDir()
	defer func() { devRoot = oldDevRoot }()

	writeFile(t, filepath.Join(devRoot, "video2"), "")
	writeFile(t, filepath.Join(devRoot, "video0"), "")
	for _, l := range []struct{ name, target string }{
		{"v4l/by-id/usb-Cam-video-index0", "../../video2"},
		{"v4l/by-path/platform-xhci-usb-0:3:1.0-video-index0", "../../video2"},
		{"v4l/by-path/platform-iris-video-index0", "../../video0"},
	} {
		p := filepath.Join(devRoot, l.name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(l.target, p); err != nil {
			t.Fatal(err)
		}
	}

	got := nodeLinks([]devNode{{name: "video2", devType: devconfig.CharDevice, major: 81, minor: 2}})
	want := []devLink{
		{name: "v4l/by-id/usb-Cam-video-index0", target: "../../video2"},
		{name: "v4l/by-path/platform-xhci-usb-0:3:1.0-video-index0", target: "../../video2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("links %+v, want %+v", got, want)
	}
}

// The container keeps the rules it was created with, in their order, and
// gets one allow rule per node.
func TestDeviceRules(t *testing.T) {
	state := containerState{rules: []*devconfig.Rule{
		{Type: devconfig.WildcardDevice, Major: -1, Minor: -1, Permissions: "rwm", Allow: false},
		{Type: devconfig.CharDevice, Major: 1, Minor: 3, Permissions: "rwm", Allow: true},
	}}
	nodes := []devNode{
		{name: "bus/usb/001/005", devType: devconfig.CharDevice, major: 189, minor: 4},
		{name: "video2", devType: devconfig.CharDevice, major: 81, minor: 2},
		{name: "video2", devType: devconfig.CharDevice, major: 81, minor: 2},
	}

	var got []string
	for _, r := range deviceRules(state, nodes) {
		got = append(got, r.CgroupString()+" "+strconv.FormatBool(r.Allow))
	}
	want := []string{"a *:* rwm false", "c 1:3 rwm true", "c 189:4 rwm true", "c 81:2 rwm true"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules %v, want %v", got, want)
	}
}

// The rules come out as runc builds them from an OCI spec: the spec's
// device cgroup rules in order, then runc's default devices, less those the
// spec has a device of its own for.
func TestSpecDeviceRules(t *testing.T) {
	major, minor := int64(81), int64(2)
	spec := &specs.Spec{Linux: &specs.Linux{
		Devices: []specs.LinuxDevice{{Path: "/dev/null", Type: "c", Major: 1, Minor: 3}},
		Resources: &specs.LinuxResources{Devices: []specs.LinuxDeviceCgroup{
			{Allow: false, Access: "rwm"},
			{Allow: true, Type: "c", Major: &major, Minor: &minor, Access: "rwm"},
		}},
	}}
	rules, err := specDeviceRules(spec)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rules {
		got = append(got, r.CgroupString()+" "+strconv.FormatBool(r.Allow))
	}
	want := []string{
		"a *:* rwm false", "c 81:2 rwm true",
		"c *:* m true", "b *:* m true",
		// no c 1:3: the spec has /dev/null itself
		"c 1:8 rwm true", "c 1:7 rwm true", "c 5:0 rwm true", "c 1:5 rwm true", "c 1:9 rwm true",
		"c 136:* rwm true", "c 5:2 rwm true", "c 10:200 rwm true",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules\n got %v\nwant %v", got, want)
	}

	if _, err := specDeviceRules(&specs.Spec{Linux: &specs.Linux{Resources: &specs.LinuxResources{
		Devices: []specs.LinuxDeviceCgroup{{Allow: true, Type: "x", Access: "rwm"}}}}}); err == nil {
		t.Error("accepted a rule of type x")
	}
}

func openDir(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

// A container can't make usbmanager write outside of its /dev by putting a
// symlink where a directory is expected.
func TestOpenDirInRootRefusesSymlinks(t *testing.T) {
	dev := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dev, "v4l")); err != nil {
		t.Fatal(err)
	}
	devFD := openDir(t, dev)
	defer unix.Close(devFD)

	if err := createLink(devFD, devLink{name: "v4l/by-id/cam", target: "../../video2"}); err == nil {
		t.Fatal("created a link through a symlinked directory")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote outside of the container: %v", entries)
	}
}

func TestCreateAndRemoveNodesAndLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mknod needs root")
	}
	oldDevRoot := devRoot
	devRoot = t.TempDir() // no host nodes: defaults to 0660 root
	defer func() { devRoot = oldDevRoot }()

	dev := t.TempDir()
	devFD := openDir(t, dev)
	defer unix.Close(devFD)

	n := devNode{name: "bus/usb/001/005", devType: devconfig.CharDevice, major: 189, minor: 4}
	if err := createNode(devFD, n); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(dev, n.name), &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(st.Rdev)) != 189 ||
		unix.Minor(uint64(st.Rdev)) != 4 || st.Mode&0o7777 != 0o660 {
		t.Fatalf("node mode %o rdev %d:%d", st.Mode, unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)))
	}

	l := devLink{name: "v4l/by-id/cam", target: "../../video2"}
	if err := createLink(devFD, l); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(dev, l.name)); err != nil || target != l.target {
		t.Fatalf("link reads %q, %v", target, err)
	}

	removeEntry(devFD, l.name)
	removeEntry(devFD, n.name)
	for _, name := range []string{l.name, n.name} {
		if _, err := os.Lstat(filepath.Join(dev, name)); !os.IsNotExist(err) {
			t.Errorf("%s still there: %v", name, err)
		}
	}
}

// containerTestEnv fakes what the reconcile worker works on: a running
// native container (its /dev under a fake /proc/<pid>/root), its device
// cgroup filter (recorded) and the directory of applied records.
type containerTestEnv struct {
	t      *testing.T
	pid    int
	filter []string // last filter set, as "<rule> <allow>"
	sets   int      // how often a filter was set
	errs   []string // what was published as passthrough errors
	fail   error    // returned by loadContainerState when set
}

const testContainerName = "app.1.1"

func newContainerTestEnv(t *testing.T) *containerTestEnv {
	if os.Geteuid() != 0 {
		t.Skip("mknod needs root")
	}
	env := &containerTestEnv{t: t, pid: 4242}
	oldState, oldProc, oldDev, oldFilter, oldApplied, oldUdev :=
		loadContainerState, procRoot, devRoot, setDeviceFilter, appliedStateDir, udevDataDir
	t.Cleanup(func() {
		loadContainerState, procRoot, devRoot, setDeviceFilter, appliedStateDir, udevDataDir =
			oldState, oldProc, oldDev, oldFilter, oldApplied, oldUdev
	})
	procRoot, devRoot, appliedStateDir = t.TempDir(), t.TempDir(), t.TempDir()
	udevDataDir = filepath.Join(t.TempDir(), "absent")
	loadContainerState = func(name string) (containerState, error) {
		if env.fail != nil {
			return containerState{}, env.fail
		}
		return containerState{pid: env.pid, cgroupDir: "/sys/fs/cgroup/eve-user-apps/" + name,
			rules: []*devconfig.Rule{{Type: devconfig.WildcardDevice, Major: -1, Minor: -1,
				Permissions: "rwm", Allow: false}}}, nil
	}
	setDeviceFilter = func(_ string, rules []*devconfig.Rule) error {
		env.sets++
		env.filter = nil
		for _, r := range rules {
			env.filter = append(env.filter, r.CgroupString()+" "+strconv.FormatBool(r.Allow))
		}
		return nil
	}
	env.newContainer(env.pid)
	return env
}

// newContainer makes an empty /dev for a container whose init is pid
func (env *containerTestEnv) newContainer(pid int) {
	env.pid = pid
	if err := os.MkdirAll(env.dev(), 0o755); err != nil {
		env.t.Fatal(err)
	}
}

func (env *containerTestEnv) dev() string {
	return filepath.Join(procRoot, strconv.Itoa(env.pid), "root", "dev")
}

func (env *containerTestEnv) controller() *usbmanagerController {
	uc := newTestUsbmanagerController()
	uc.publishPassthroughError = func(_, errStr string) { env.errs = append(env.errs, errStr) }
	return uc
}

func (env *containerTestEnv) expectNodes(present bool, names ...string) {
	env.t.Helper()
	for _, n := range names {
		_, err := os.Lstat(filepath.Join(env.dev(), n))
		if present && err != nil {
			env.t.Errorf("%s not in the container: %v", n, err)
		}
		if !present && !os.IsNotExist(err) {
			env.t.Errorf("%s still in the container: %v", n, err)
		}
	}
}

func (env *containerTestEnv) expectFilter(want ...string) {
	env.t.Helper()
	if !reflect.DeepEqual(env.filter, want) {
		env.t.Fatalf("filter %v, want %v", env.filter, want)
	}
}

// connect and disconnect are what the controller does under its lock; the
// worker then reconciles
func connectAndReconcile(uc *usbmanagerController, up usbpassthrough) {
	uc.Lock()
	uc.connectUSBDeviceToContainer(up)
	uc.Unlock()
	uc.reconcileQueuedContainers()
}

func disconnectAndReconcile(uc *usbmanagerController, up usbpassthrough) {
	uc.Lock()
	uc.disconnectUSBDeviceFromContainer(up)
	uc.Unlock()
	uc.reconcileQueuedContainers()
}

func cameraPassthrough(sys string) usbpassthrough {
	ud := usbdevice{busnum: 1, portnum: "3", devnum: 5, ueventFilePath: filepath.Join(sys, "uevent")}
	vm := newContainerTarget(testContainerName, []string{"VIDEO"})
	return usbpassthrough{usbdevice: &ud, vm: &vm}
}

// Connecting and disconnecting a usb device to a native container creates
// and removes its nodes in the container's /dev and allows and disallows
// them in its device cgroup.
func TestConnectDisconnectContainer(t *testing.T) {
	env := newContainerTestEnv(t)
	uc := env.controller()
	up := cameraPassthrough(fakeCamera(t))

	connectAndReconcile(uc, up)
	env.expectFilter("a *:* rwm false", "c 189:4 rwm true", "c 81:2 rwm true", "c 81:3 rwm true")
	env.expectNodes(true, "bus/usb/001/005", "video2", "video3")
	env.expectNodes(false, "bus/usb/001/006")
	if _, ok := readAppliedRecord(testContainerName); !ok {
		t.Error("no applied record")
	}

	disconnectAndReconcile(uc, up)
	env.expectFilter("a *:* rwm false")
	env.expectNodes(false, "bus/usb/001/005", "video2", "video3")
	if len(uc.applied) != 0 {
		t.Errorf("applied state left: %+v", uc.applied)
	}
	if _, ok := readAppliedRecord(testContainerName); ok {
		t.Error("applied record left")
	}
}

// After usbmanager restarts, a container that had a device unplugged
// meanwhile loses its nodes and their allow rules, though nothing in the new
// usbmanager ever passed the device through.
func TestReconcileAfterRestartRemovesStaleDevices(t *testing.T) {
	env := newContainerTestEnv(t)
	connectAndReconcile(env.controller(), cameraPassthrough(fakeCamera(t)))
	env.expectNodes(true, "video2")

	restarted := env.controller()
	restarted.Lock()
	restarted.wantContainer(testContainerName) // its domain is RUNNING
	restarted.Unlock()
	restarted.reconcileQueuedContainers()
	env.expectFilter("a *:* rwm false")
	env.expectNodes(false, "bus/usb/001/005", "video2", "video3")
	if _, ok := readAppliedRecord(testContainerName); ok {
		t.Error("applied record left")
	}
}

// A container that never had a device is left alone: its runtime's filter
// is not replaced, and containerd is not even asked.
func TestReconcileLeavesOtherContainersAlone(t *testing.T) {
	env := newContainerTestEnv(t)
	env.fail = errors.New("containerd asked")
	uc := env.controller()
	uc.Lock()
	uc.wantContainer(testContainerName)
	uc.containerQueue.add(testContainerName)
	uc.Unlock()
	uc.reconcileQueuedContainers()
	if env.sets != 0 || len(env.errs) != 0 {
		t.Fatalf("filter set %d times, errors %v", env.sets, env.errs)
	}
}

// A container recreated while its domain stayed RUNNING starts with its
// spec's filter and an empty /dev; the resync gives it its devices again.
func TestResyncRestoresRecreatedContainer(t *testing.T) {
	env := newContainerTestEnv(t)
	uc := env.controller()
	connectAndReconcile(uc, cameraPassthrough(fakeCamera(t)))

	uc.queueContainersWithDevices()
	uc.reconcileQueuedContainers()
	if env.sets != 1 {
		t.Fatalf("filter set %d times for an unchanged container, want 1", env.sets)
	}

	env.newContainer(4343)
	uc.queueContainersWithDevices()
	uc.reconcileQueuedContainers()
	if env.sets != 2 {
		t.Fatalf("filter set %d times after the container was recreated, want 2", env.sets)
	}
	env.expectFilter("a *:* rwm false", "c 189:4 rwm true", "c 81:2 rwm true", "c 81:3 rwm true")
	env.expectNodes(true, "bus/usb/001/005", "video2", "video3")
}

// What goes wrong is published once, and cleared once it works again.
func TestReconcileReportsErrors(t *testing.T) {
	env := newContainerTestEnv(t)
	uc := env.controller()
	env.fail = errors.New("container app.1.1 is stopped")
	up := cameraPassthrough(fakeCamera(t))
	connectAndReconcile(uc, up)
	uc.queueContainersWithDevices()
	uc.reconcileQueuedContainers()
	if want := []string{"container app.1.1 is stopped"}; !reflect.DeepEqual(env.errs, want) {
		t.Fatalf("published %q, want %q", env.errs, want)
	}

	env.fail = nil
	uc.queueContainersWithDevices()
	uc.reconcileQueuedContainers()
	if want := []string{"container app.1.1 is stopped", ""}; !reflect.DeepEqual(env.errs, want) {
		t.Fatalf("published %q, want %q", env.errs, want)
	}
	env.expectNodes(true, "video2")
}

// The worker does its work without the controller's lock, so a slow device
// can't hold up usbmanager for other domains.
func TestReconcileRunsWithoutTheLock(t *testing.T) {
	env := newContainerTestEnv(t)
	uc := env.controller()
	locked := false
	setDeviceFilter = func(string, []*devconfig.Rule) error {
		if uc.TryLock() {
			uc.Unlock()
		} else {
			locked = true
		}
		return nil
	}
	connectAndReconcile(uc, cameraPassthrough(fakeCamera(t)))
	if locked {
		t.Fatal("the device filter was set under the controller's lock")
	}
}

// A camera's /dev/videoN comes after the usb device bound, when its interface
// driver probes: the container gets it then, and loses it again when it goes.
func TestRefreshContainerDevicesFollowsLateNodes(t *testing.T) {
	env := newContainerTestEnv(t)
	uc := env.controller()

	// the camera as it is when it binds: no video interface yet
	sys := filepath.Join(t.TempDir(), "1-3")
	writeFile(t, filepath.Join(sys, "devnum"), "5\n")
	writeFile(t, filepath.Join(sys, "uevent"), "MAJOR=189\nMINOR=4\nDEVNAME=bus/usb/001/005\n")
	connectAndReconcile(uc, cameraPassthrough(sys))
	env.expectFilter("a *:* rwm false", "c 189:4 rwm true")

	video := filepath.Join(sys, "1-3:1.0", "video4linux", "video2")
	writeFile(t, filepath.Join(video, "uevent"), "MAJOR=81\nMINOR=2\nDEVNAME=video2\n")
	uc.refreshContainerDevices(video)
	uc.reconcileQueuedContainers()
	env.expectFilter("a *:* rwm false", "c 189:4 rwm true", "c 81:2 rwm true")
	env.expectNodes(true, "video2")

	if err := os.RemoveAll(filepath.Join(sys, "1-3:1.0")); err != nil {
		t.Fatal(err)
	}
	uc.refreshContainerDevices(video)
	uc.reconcileQueuedContainers()
	env.expectFilter("a *:* rwm false", "c 189:4 rwm true")
	env.expectNodes(false, "video2")

	// an event below another usb device queues nothing
	uc.refreshContainerDevices("/sys/devices/elsewhere/2-1/2-1:1.0/video4linux/video9")
	if names := uc.containerQueue.take(); len(names) != 0 {
		t.Fatalf("queued %v for an unrelated event", names)
	}
}
