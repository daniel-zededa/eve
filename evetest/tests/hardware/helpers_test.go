// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware_test

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// Logical name of the (single) edge device used by every test in this package.
	devName = "hardware-dev"

	// The single management port every test in this package configures.
	// portLogicalLabel is what the controller calls it; portIfName is the
	// underlying Linux interface.
	portLogicalLabel = "ethernet0"
	portIfName       = "eth0"

	// Image of the general-purpose test container (ships sshd). Deployed as
	// HVM, EVE runs it inside a QEMU domain, which is what USB passthrough
	// attaches to.
	ubuntuCtrImage = "lfedge/evetest-ubuntu-ctr"
	ubuntuCtrTag   = "1.0"
	// ubuntuCtrNativeTag is the first version of the image whose sshd also
	// starts in a native container (NOHYPER), where /run is an empty tmpfs.
	// It is served from evetest's local registry (see
	// usbContainerAppImage), so a locally built image works before it is
	// published.
	ubuntuCtrNativeTag = "1.4"

	// Local network instance connecting the apps, and the first of the ports
	// on the edge node forwarded to their sshd: every app the factory starts
	// gets the next one, since two apps cannot share a forwarded port.
	niDisplayName     = "local-ni"
	niSubnet          = "10.11.12.0/24"
	niGateway         = "10.11.12.1"
	appSSHFwdPortBase = 2222

	// usbFlashLabel names the flash drive in the device model when claimed by
	// its exact bus and port, usbFlashWildcardLabel when claimed by a bus-wide
	// wildcard, and usbClaimLabelPrefix followed by the claimed port path, e.g.
	// "usb-claim-1.1.*", the entries of TestUSBHubChain. A label serves as
	// logical label, physical label and assignment group alike: domainmgr
	// resolves an app adapter name by group, then physical, then logical
	// label, and usbmanager keys on the physical label.
	usbFlashLabel         = "usb-flash"
	usbFlashWildcardLabel = "usb-flash-wildcard"
	usbClaimLabelPrefix   = "usb-claim-"

	// devInfoTimeout covers ZInfoDevice reflecting a change to the assignable
	// adapters after a config apply.
	devInfoTimeout = 5 * time.Minute
	// appRunningTimeout excludes the image download.
	appRunningTimeout = 10 * time.Minute
)

// Credentials baked into the evetest-ubuntu-ctr image.
var appAuth = evetest.UsernamePasswordAuth{
	Username: "root",
	Password: "testpassword",
}

// setupHardwareTestDevice declares the prerequisites shared by every test in
// this package and returns a handle to the device. They are stated in one
// place because the framework compares device requirements field by field to
// decide whether the VM from the previous test can be reused. Every test here
// changes the device's hardware through the hypervisor, so the suite is
// skipped on a provider without QMP access.
func setupHardwareTestDevice(hypervisor evetest.Hypervisor) *evetest.EdgeDevice {
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
		evetest.RequireCapabilities{
			Capabilities: []api.Capability{api.Capability_CAPABILITY_QMP},
		},
	)
	return evetest.GetEdgeDevice(devName)
}

// singleMgmtPortConfig builds the device configuration the tests in this
// package start from: one DHCP-configured management+apps port and nothing
// else. Tests add the network instance, model entries and apps they need.
func singleMgmtPortConfig() *evetest.EdgeDeviceConfig {
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  portLogicalLabel,
		PhysicalLabel: portIfName,
		InterfaceName: portIfName,
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	return devConfig
}

// addLocalNI adds the local network instance the app is connected to:
// niSubnet on the management port.
func addLocalNI(devConfig *evetest.EdgeDeviceConfig) uuid.UUID {
	return devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: niDisplayName,
		Port:        portLogicalLabel,
		Subnet:      evetest.IPSubnet(niSubnet),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress(niGateway),
		MTU:     1500,
	})
}

// singleVIFWithSSH describes the app network adapter used to run commands
// inside the application: a VIF on the local NI, the sshd port forwarded from
// the edge node's sshFwdPort, and an allow-all ACL.
func singleVIFWithSSH(niUUID uuid.UUID, sshFwdPort uint16) []evetest.AppNetworkAdapter {
	return []evetest.AppNetworkAdapter{
		evetest.VirtualNetworkAdapter{
			LogicalLabel:        "vif0",
			NetworkInstanceUUID: niUUID,
			PortFwdRules: []evetest.PortFwdRule{
				{
					Protocol:     evetest.NetworkProtocolTCP,
					EdgeNodePort: sshFwdPort,
					AppPort:      22,
				},
			},
			ACLAllowRules: []evetest.ACLAllowRule{
				{
					Protocol:     evetest.NetworkProtocolAny,
					RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
				},
			},
		},
	}
}

// usbFlashPhysicalIO models the flash drive as an assignable USB device.
func usbFlashPhysicalIO(name, usbAddr string) evetest.PhysicalIOConfig {
	return evetest.PhysicalIOConfig{
		LogicalLabel:    name,
		PhysicalLabel:   name,
		AssignmentGroup: name,
		Type:            evecommon.PhyIoType_PhyIoUSBDevice,
		USBAddress:      usbAddr,
		Usage:           evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	}
}

// usbProductPhysicalIO models a USB device as assignable by its ids,
// "vvvv:pppp", whatever port it is plugged into.
func usbProductPhysicalIO(name, usbProduct string) evetest.PhysicalIOConfig {
	return evetest.PhysicalIOConfig{
		LogicalLabel:    name,
		PhysicalLabel:   name,
		AssignmentGroup: name,
		Type:            evecommon.PhyIoType_PhyIoUSBDevice,
		USBProduct:      usbProduct,
		Usage:           evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	}
}

// usbFlashAppConfig is the application the drive is assigned to: the ubuntu
// test container as an HVM domain, reachable over SSH through the local NI
// on the edge node's sshFwdPort, named after its adapter.
func usbFlashAppConfig(ioAdapterName string, niUUID uuid.UUID,
	sshFwdPort uint16) evetest.ApplicationInstanceConfig {
	return usbAppConfig(ioAdapterName, evetest.DockerContainer{
		ImageName: ubuntuCtrImage,
		Tag:       ubuntuCtrTag,
	}, eveconfig.VmMode_HVM, []string{ioAdapterName}, niUUID, sshFwdPort)
}

// usbContainerAppImage pushes the ubuntu test container in the version that
// also runs natively (ubuntuCtrNativeTag) into evetest's local registry, from
// the local Docker daemon or pulled from Docker Hub, and returns the image
// reference EVE pulls it by.
func usbContainerAppImage() (evetest.DockerContainer, error) {
	return evetest.PushDockerImageToLocalRegistry(ubuntuCtrImage + ":" + ubuntuCtrNativeTag)
}

// usbAppConfig is the ubuntu test container image run in the given
// virtualization mode (HVM: in a shim VM; NOHYPER: as a native container on
// EVE's kernel) with the given USB devices directly assigned, reachable over
// SSH through the local NI on the edge node's sshFwdPort.
func usbAppConfig(displayName string, image evetest.DockerContainer, mode eveconfig.VmMode,
	ioAdapterNames []string, niUUID uuid.UUID, sshFwdPort uint16) evetest.ApplicationInstanceConfig {
	ioAdapters := make([]evetest.IOAdapterConfig, 0, len(ioAdapterNames))
	for _, name := range ioAdapterNames {
		ioAdapters = append(ioAdapters, evetest.IOAdapterConfig{
			LogicalLabel: name,
			Type:         evecommon.PhyIoType_PhyIoUSBDevice,
		})
	}
	return evetest.ApplicationInstanceConfig{
		DisplayName:        displayName,
		Activate:           true,
		Image:              image,
		VirtualizationMode: mode,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters:    singleVIFWithSSH(niUUID, sshFwdPort),
		IOAdapters:         ioAdapters,
	}
}

// usbFlashApps deploys applications that have the flash drive assigned. It
// holds what all of them share: the device, its configuration and the local
// network instance they hang off, which the factory adds to the configuration
// (applied together with the first app), and it counts the apps started so
// that each gets its own forwarded SSH port.
type usbFlashApps struct {
	t         *WithT
	device    *evetest.EdgeDevice
	devConfig *evetest.EdgeDeviceConfig
	niUUID    uuid.UUID
	started   uint16
}

func newUSBFlashApps(t *WithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig) *usbFlashApps {
	return &usbFlashApps{
		t:         t,
		device:    device,
		devConfig: devConfig,
		niUUID:    addLocalNI(devConfig),
	}
}

// start models the drive as the PhysicalIO label claiming usbAddr, deploys the
// ubuntu test container with that adapter and returns once the app is RUNNING
// and answers over SSH.
func (f *usbFlashApps) start(label, usbAddr string) *usbFlashApp {
	evetest.Logger().Infof("Deploying app with the flash drive claimed as %q by usbaddr %q",
		label, usbAddr)
	f.devConfig.AddPhysicalIO(usbFlashPhysicalIO(label, usbAddr))
	appUUID := f.devConfig.AddApplication(
		usbFlashAppConfig(label, f.niUUID, appSSHFwdPortBase+f.started))
	f.started++
	f.device.ApplyConfig(f.devConfig, true, false)
	f.device.WaitUntilAppIsRunning(appUUID, appRunningTimeout)
	waitForAppSSH(f.t, f.device, appUUID)
	return &usbFlashApp{apps: f, label: label, uuid: appUUID}
}

// usbFlashApp is one running application with the drive assigned.
type usbFlashApp struct {
	apps  *usbFlashApps
	label string
	uuid  uuid.UUID
}

// usbDevices lists the USB devices the app's kernel enumerates; a method value
// for Eventually.
func (a *usbFlashApp) usbDevices() (evetest.USBDeviceList, error) {
	return a.apps.device.ListUSBDevicesInsideApp(a.uuid, appAuth)
}

// stop deletes the app, waits until the device reports it gone, and only then
// removes its model entry and applies. A confirmed config apply says nothing
// about the domain teardown, which releases the adapter some thirty seconds
// after the app is halted, and removing the entry before that used to crash
// domainmgr.
func (a *usbFlashApp) stop() {
	deleteAppAndWait(a.apps.t, a.apps.device, a.apps.devConfig, a.uuid)
	a.apps.devConfig.DeletePhysicalIO(a.label)
	a.apps.device.ApplyConfig(a.apps.devConfig, true, false)
}

// lookupAssignableAdapter returns the reported assignable adapter (group)
// named label or having label among its members, or nil.
func lookupAssignableAdapter(dinfo *eveinfo.ZInfoDevice, label string) *eveinfo.ZioBundle {
	for _, bundle := range dinfo.GetAssignableAdapters() {
		if bundle.GetName() == label {
			return bundle
		}
		for _, member := range bundle.GetMembers() {
			if member == label {
				return bundle
			}
		}
	}
	return nil
}

// adapterUsedBy is a predicate over ZInfoDevice: the adapter is reported
// without error and as assigned to the given application.
func adapterUsedBy(label string, appUUID uuid.UUID) func(*eveinfo.ZInfoDevice) bool {
	return func(dinfo *eveinfo.ZInfoDevice) bool {
		bundle := lookupAssignableAdapter(dinfo, label)
		return bundle != nil && bundle.GetErr() == nil &&
			bundle.GetUsedByAppUUID() == appUUID.String()
	}
}

// adaptersUsedBy is a predicate over ZInfoDevice: the adapter of every one of
// the apps is reported without error and as assigned to that app.
func adaptersUsedBy(apps []*usbFlashApp) func(*eveinfo.ZInfoDevice) bool {
	return func(dinfo *eveinfo.ZInfoDevice) bool {
		for _, app := range apps {
			if !adapterUsedBy(app.label, app.uuid)(dinfo) {
				return false
			}
		}
		return true
	}
}

// hasUSBDevice is a predicate over a USB device list: a device with the given
// serial number is enumerated.
func hasUSBDevice(serial string) func(evetest.USBDeviceList) bool {
	return func(list evetest.USBDeviceList) bool {
		return list.FindBySerial(serial) != nil
	}
}

// lacksUSBDevice is a predicate over a USB device list: no device with the
// given serial number is enumerated.
func lacksUSBDevice(serial string) func(evetest.USBDeviceList) bool {
	return func(list evetest.USBDeviceList) bool {
		return list.FindBySerial(serial) == nil
	}
}

// hasUSBDevicesAt is a predicate over a USB device list: on the given bus,
// every one of the port paths holds a device with the given vendor and
// product id.
func hasUSBDevicesAt(bus uint16, ports []string,
	vendorID, productID uint16) func(evetest.USBDeviceList) bool {
	return func(list evetest.USBDeviceList) bool {
		for _, port := range ports {
			found := false
			for _, dev := range list {
				if dev.Bus == bus && dev.Port == port &&
					dev.VendorID == vendorID && dev.ProductID == productID {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
}

// waitForAppSSH blocks until commands can be executed inside the application
// over the port-forwarded sshd. Reaching RUNNING only means the domain was
// created; sshd inside the container needs more time to accept connections.
func waitForAppSSH(t *WithT, device *evetest.EdgeDevice, appUUID uuid.UUID) {
	const (
		sshTimeout = 20 * time.Second
		timeout    = 3 * time.Minute
		polling    = 5 * time.Second
	)
	evetest.Logger().Infof("Waiting for app %q SSH to become reachable...", appUUID)
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"echo hello", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("hello"))
	}, timeout, polling).Should(Succeed())
}

// deleteAppAndWait removes the application from the device configuration,
// applies it, and blocks until the device reports the instance as gone, so
// that teardown cannot race the device-config reset before the next test.
func deleteAppAndWait(t *WithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, appUUID uuid.UUID) {
	const timeout = 5 * time.Minute
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Application instance is deleted",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
}

// containerUSBApp is the ubuntu test container with USB devices assigned, run
// natively or in a shim VM, as seen from inside: its device nodes. Inside a
// native container /sys is EVE's own, so a USB device is enumerated there
// whether or not it is passed through; what passthrough gives a container is
// the device's nodes in its /dev and the right to open them, and that is
// what these probes look at.
type containerUSBApp struct {
	device *evetest.EdgeDevice
	uuid   uuid.UUID
}

// appScriptTimeout bounds one probe run inside the app over SSH.
const appScriptTimeout = 30 * time.Second

// run executes a shell script inside the app and returns its stdout.
func (a *containerUSBApp) run(script string) (string, error) {
	stdout, _, err := a.device.RunShellScriptInsideApp(a.uuid, appAuth, script,
		appScriptTimeout, 0)
	return stdout, err
}

// serialPort is what the app sees of a USB serial adapter: the
// /dev/serial/by-id link carrying its serial number, the node it resolves to,
// the node's mode and whether the node can be opened.
type serialPort struct {
	Link string // name in /dev/serial/by-id, "" when there is none
	Node string // e.g. /dev/ttyUSB0, "" when the link resolves to no tty node
	Mode string // octal permission bits, e.g. "660"
	// Major and Minor are the node's device numbers.
	Major, Minor int
	Open         bool
}

func (p serialPort) String() string {
	if p.Link == "" {
		return "no serial port"
	}
	return fmt.Sprintf("link %s -> node %q mode %s open %v", p.Link, p.Node, p.Mode, p.Open)
}

// serialPortScript prints the serialPort of the adapter with serial number
// $1 as key=value lines. stty opens the node non-blocking, which a tty
// without carrier needs, and fails with EPERM when the device cgroup denies
// it.
const serialPortScript = `
l=$(ls /dev/serial/by-id/ 2>/dev/null | grep -F -- "$1" | head -1)
[ -n "$l" ] || exit 0
echo "link=$l"
n=$(readlink -f "/dev/serial/by-id/$l")
[ -c "$n" ] || exit 0
echo "node=$n"
echo "mode=$(stat -c %a "$n")"
echo "dev=$(stat -c %t:%T "$n")"
if stty -F "$n" >/dev/null 2>&1; then echo open=yes; else echo open=no; fi
`

// serialPort probes the USB serial adapter with the given serial number; a
// method value for Eventually.
func (a *containerUSBApp) serialPort(serial string) func() (serialPort, error) {
	return func() (serialPort, error) {
		out, err := a.run(withArgs(serialPortScript, serial))
		if err != nil {
			return serialPort{}, err
		}
		kv := parseKeyValues(out)
		port := serialPort{Link: kv["link"], Node: kv["node"], Mode: kv["mode"],
			Open: kv["open"] == "yes"}
		if major, minor, ok := strings.Cut(kv["dev"], ":"); ok {
			// stat prints device numbers in hex
			maj, err1 := strconv.ParseInt(major, 16, 32)
			mnr, err2 := strconv.ParseInt(minor, 16, 32)
			if err1 != nil || err2 != nil {
				return port, fmt.Errorf("unexpected device numbers %q", kv["dev"])
			}
			port.Major, port.Minor = int(maj), int(mnr)
		}
		return port, nil
	}
}

// blockDiskScript prints node=<dev> and read=yes|no for the disk of the USB
// device with serial number $1, found through sysfs (EVE's, in a native
// container), or nothing when there is no such disk or no node for it in
// /dev.
const blockDiskScript = `
for b in /sys/block/sd*; do
  [ -e "$b" ] || continue
  d=$(readlink -f "$b/device")
  while [ -n "$d" ] && [ "$d" != / ]; do
    if [ -f "$d/serial" ] && [ "$(cat "$d/serial")" = "$1" ]; then
      n=/dev/${b##*/}
      [ -b "$n" ] || exit 0
      echo "node=$n"
      if dd if="$n" of=/dev/null bs=512 count=1 2>/dev/null; then echo read=yes; else echo read=no; fi
      exit 0
    fi
    d=${d%/*}
  done
done
`

// blockDisk is what the app sees of a USB flash drive: its disk node and
// whether the first sector can be read.
type blockDisk struct {
	Node string // e.g. /dev/sda, "" when the app has no node for the drive
	Read bool
}

func (b blockDisk) String() string {
	if b.Node == "" {
		return "no disk node"
	}
	return fmt.Sprintf("node %s readable %v", b.Node, b.Read)
}

// blockDisk probes the flash drive with the given serial number; a method
// value for Eventually.
func (a *containerUSBApp) blockDisk(serial string) func() (blockDisk, error) {
	return func() (blockDisk, error) {
		out, err := a.run(withArgs(blockDiskScript, serial))
		if err != nil {
			return blockDisk{}, err
		}
		kv := parseKeyValues(out)
		return blockDisk{Node: kv["node"], Read: kv["read"] == "yes"}, nil
	}
}

// canOpenCharDevice makes a char device node for major:minor in the app's
// /tmp and reports whether it can be opened. In a native container a device
// it wasn't given is refused by the device cgroup, at mknod or at open.
func (a *containerUSBApp) canOpenCharDevice(major, minor int) (bool, error) {
	out, err := a.run(fmt.Sprintf(`
n=/tmp/evtest-chardev
rm -f "$n"
if mknod "$n" c %d %d 2>/dev/null && stty -F "$n" >/dev/null 2>&1; then echo open=yes; else echo open=no; fi
rm -f "$n"
`, major, minor))
	if err != nil {
		return false, err
	}
	return parseKeyValues(out)["open"] == "yes", nil
}

// containerDefaultDevices are devices every container may use, allowed by
// the container runtime rather than the app's spec (runc's default devices):
// passing a USB device in rebuilds the native container's device cgroup, which
// must keep allowing them. /dev/tty is left out: over SSH without a terminal
// it fails for want of a controlling terminal, not for want of permission.
var containerDefaultDevices = []string{"/dev/null", "/dev/zero", "/dev/full",
	"/dev/urandom", "/dev/ptmx"}

// unusableDefaultDevices returns those of containerDefaultDevices the app
// cannot open, empty when it can open them all.
func (a *containerUSBApp) unusableDefaultDevices() ([]string, error) {
	out, err := a.run(withArgs(`for d in "$@"; do ( : <> "$d" ) 2>/dev/null || echo "fail=$d"; done`,
		containerDefaultDevices...))
	if err != nil {
		return nil, err
	}
	var failed []string
	for _, line := range strings.Split(out, "\n") {
		if dev, ok := strings.CutPrefix(strings.TrimSpace(line), "fail="); ok {
			failed = append(failed, dev)
		}
	}
	return failed, nil
}

// bootMarkerPath is a file in the app's /dev/shm, a tmpfs of its own whether
// it runs natively or in a shim VM, so it is gone once the app restarts.
const bootMarkerPath = "/dev/shm/evtest-boot-marker"

// writeBootMarker leaves a random marker in the app and returns it.
func (a *containerUSBApp) writeBootMarker() (string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	marker := id.String()
	_, err = a.run(fmt.Sprintf("echo %s > %s", marker, bootMarkerPath))
	return marker, err
}

// bootMarker reads the marker back; it differs once the app has restarted.
func (a *containerUSBApp) bootMarker() (string, error) {
	out, err := a.run("cat " + bootMarkerPath + " 2>/dev/null")
	return strings.TrimSpace(out), err
}

// hostCharDeviceMode returns the permission bits of a node in EVE's own /dev,
// e.g. "660", or "" when there is no such node.
func hostCharDeviceMode(device *evetest.EdgeDevice, node string) (string, error) {
	out, _, err := device.RunShellScript(
		fmt.Sprintf("stat -c %%a %s 2>/dev/null", node), appScriptTimeout, 0)
	return strings.TrimSpace(out), err
}

// withArgs prefixes a script with "set --" so that it sees args as $1, $2...
func withArgs(script string, args ...string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return "set -- " + strings.Join(quoted, " ") + "\n" + script
}

// parseKeyValues parses key=value lines; other lines are ignored.
func parseKeyValues(out string) map[string]string {
	kv := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			kv[key] = value
		}
	}
	return kv
}
