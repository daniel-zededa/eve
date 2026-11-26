// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware_test

import (
	"fmt"
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
)

const (
	// containerModeParamKey selects how the app the devices are assigned to
	// runs: "native" (VmMode NOHYPER, a container on EVE's own kernel) or
	// "shim" (VmMode HVM, a container in a shim VM of its own).
	containerModeParamKey = "CONTAINER_MODE"
	containerModeNative   = "native"
	containerModeShim     = "shim"

	// serialAdapterID names the hot-plugged USB serial adapter towards the
	// hypervisor and is its USB serial number, which the /dev/serial/by-id
	// link carries; serialHubID names the hub it is re-plugged behind.
	serialAdapterID = "evtest-serial"
	serialHubID     = "evtest-serial-hub"
	// containerFlashDriveID names the flash drive of this test.
	containerFlashDriveID = "evtest-ctr-flash"

	// The device model claims both devices by their ids, so they match on
	// whatever port they are plugged into. 46f4:0001 is QEMU's usb-storage.
	usbSerialLabel    = "usb-serial"
	usbSerialProduct  = "0403:6001"
	usbCtrFlashLabel  = "usb-ctr-flash"
	usbFlashProduct   = "46f4:0001"
	containerAppLabel = "usb-container-app"

	// ttyS0, a char device every EVE VM has and no app is given.
	unassignedCharMajor = 4
	unassignedCharMinor = 64
)

var containerModeParam = evetest.TestParameterDefinition{
	Key:          containerModeParamKey,
	DefaultValue: containerModeNative,
	Description: evetest.TestParameterDescription{
		Summary:       "How the app with the USB devices runs: natively (NOHYPER) or in a shim VM (HVM)",
		Default:       "native",
		AllowedValues: "native|shim",
	},
}

// TestUSBHotplugIntoContainer verifies that USB devices hot-plugged into the
// running device reach a container app they are assigned to, as device nodes
// it can use, follow unplugging and re-plugging into another port while the
// app runs, and, for a native container, that the app can use only the
// devices it was given.
//
// A container app runs in one of two ways (CONTAINER_MODE). In a shim VM
// (HVM), usbmanager hot-plugs a matching device into the VM's QEMU like for
// any VM, and the container sees the VM's /dev: the VM's init has to load the
// device's driver and add the /dev/serial/by-id link udev would add. A native
// container (NOHYPER) shares EVE's kernel and has no QEMU: usbmanager gives it
// the device's nodes and links in its own /dev, and allows them in its device
// cgroup (an eBPF filter on cgroup v2), and takes both away on unplug.
//
// The devices are QEMU's emulated USB serial adapter, an FTDI FT232 driven by
// ftdi_sio, which EVE builds as a module and which creates /dev/ttyUSBN only
// after the USB device itself has bound (EdgeDevice.AttachUSBSerial), and, in
// native mode, the usb-storage flash drive of TestUSBFlashDriveHotplug for a
// block node. Inside a native container /sys is EVE's own, so whether a
// device is enumerated there says nothing about passthrough; the test looks
// at the app's /dev instead: the /dev/serial/by-id link with the adapter's
// serial number, the node it resolves to and whether it opens, and the
// drive's disk node and whether its first sector reads. Whether the app
// restarted is told by a marker in its /dev/shm, a tmpfs of its own in both
// modes.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- as in TestUSBFlashDriveHotplug.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps).
//   - From phase 2: a local network instance on eth0; PhysicalIO entries of
//     type USB device "usb-serial" claiming usbproduct 0403:6001 and
//     "usb-ctr-flash" claiming 46f4:0001, each in an assignment group of its
//     own; the ubuntu test container in the CONTAINER_MODE's VmMode with a VIF
//     on the network instance (sshd port-forwarded) and both entries as
//     directly assigned adapters.
//
// Phases / assertions
// -------------------
//
//  1. setup-done -> config-applied.
//
//  2. app-running: with nothing plugged in, the app reaches RUNNING, answers
//     over SSH, and ZInfoDevice reports both entries as used by it. A boot
//     marker is written into the app.
//
//  3. serial-passed-through: the serial adapter is plugged in. The app gets a
//     /dev/serial/by-id link with its serial number to a tty node it can
//     open. In native mode the node has the mode the node has on EVE, i.e.
//     the one udev gave it, not devtmpfs's 0600, and the app can still open
//     the devices the container runtime allows every container (/dev/null,
//     /dev/ptmx, ...): passing a device in rebuilds its device cgroup.
//
//  4. flash-drive-passed-through (native mode): the flash drive is plugged
//     in. The app gets a disk node for it whose first sector it can read.
//
//  5. devices-unplugged: both are unplugged. The link and the nodes leave the
//     app; in native mode a node made by the app for the adapter's old device
//     numbers no longer opens, while the runtime's default devices still do.
//     The boot marker is unchanged: the app ran on.
//
//  6. serial-replugged-elsewhere: a hub is plugged in and the adapter behind
//     it, a port path the app's claim never named. The app gets the link and
//     an openable node again, still without restarting.
//
//  7. unassigned-device-refused (native mode): a node the app makes for a
//     device it was not given (ttyS0) does not open, while the adapter's
//     does. The adapter, the hub and the app are removed at the end, so the
//     device is clean for the next test.
//
// Test params
// -----------
//   - HYPERVISOR. The test skips unless it is KVM, where usbmanager runs.
//   - CONTAINER_MODE (native|shim). The suite runs both.
//
// Suite placement
// ---------------
//   - TestHardwareSuite.
func TestUSBHotplugIntoContainer(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		containerModeParam,
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	if hypervisor != evetest.HypervisorKVM {
		evetestT.Skipf("HYPERVISOR is %s: USB passthrough to applications is done by "+
			"usbmanager, which runs under KVM only", hypervisor)
	}
	mode := evetest.GetTestParameter[string](containerModeParamKey)
	var vmMode eveconfig.VmMode
	switch mode {
	case containerModeNative:
		vmMode = eveconfig.VmMode_NOHYPER
	case containerModeShim:
		vmMode = eveconfig.VmMode_HVM
	default:
		evetestT.Fatalf("%s must be %q or %q, not %q", containerModeParamKey,
			containerModeNative, containerModeShim, mode)
	}
	native := mode == containerModeNative

	// Set up the test harness and specify the test prerequisites.
	device := setupHardwareTestDevice(hypervisor)
	evetest.Checkpoint("setup-done")

	// Build and apply the device configuration.
	devConfig := singleMgmtPortConfig()
	device.ApplyConfig(devConfig, true, false)
	evetest.Checkpoint("config-applied")

	// Phase 2: the app with both devices assigned, none plugged in yet.
	image, err := usbContainerAppImage()
	t.Expect(err).ToNot(HaveOccurred(), "the test container image in evetest's local registry")
	niUUID := addLocalNI(devConfig)
	devConfig.AddPhysicalIO(usbProductPhysicalIO(usbSerialLabel, usbSerialProduct))
	devConfig.AddPhysicalIO(usbProductPhysicalIO(usbCtrFlashLabel, usbFlashProduct))
	appUUID := devConfig.AddApplication(usbAppConfig(containerAppLabel, image, vmMode,
		[]string{usbSerialLabel, usbCtrFlashLabel}, niUUID, appSSHFwdPortBase))
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, false)
	device.WaitUntilAppIsRunning(appUUID, appRunningTimeout)
	waitForAppSSH(t, device, appUUID)
	t.Eventually(devUpdates, devInfoTimeout).Should(Receive(matchers.SatisfyPredicate(
		"both devices are reported as used by the app", func(dinfo *eveinfo.ZInfoDevice) bool {
			return adapterUsedBy(usbSerialLabel, appUUID)(dinfo) &&
				adapterUsedBy(usbCtrFlashLabel, appUUID)(dinfo)
		})))
	app := &containerUSBApp{device: device, uuid: appUUID}
	var marker string
	marker, err = app.writeBootMarker()
	t.Expect(err).ToNot(HaveOccurred())
	evetest.Checkpoint("app-running")

	usableSerialPort := matchers.SatisfyPredicate(
		"the app has the adapter's by-id link to a tty node it can open",
		func(p serialPort) bool { return p.Link != "" && p.Node != "" && p.Open })

	// Phase 3: the serial adapter reaches the app as a usable tty.
	device.AttachUSBSerial(serialAdapterID)
	device.WaitForUSBDevice(t, serialAdapterID, usbEnumerationTimeout, usbEnumerationInterval)
	t.Eventually(app.serialPort(serialAdapterID), usbEnumerationTimeout,
		usbEnumerationInterval).Should(usableSerialPort)
	port, err := app.serialPort(serialAdapterID)()
	t.Expect(err).ToNot(HaveOccurred())
	evetest.Logger().Infof("The app has the serial adapter as %s", port)
	if native {
		// The node's mode is copied from EVE's node once udev set it there.
		t.Expect(hostCharDeviceMode(device, port.Node)).To(Equal(port.Mode),
			"the app's node has the mode of EVE's node")
		// The rebuilt device cgroup still allows what runc allows every
		// container.
		t.Expect(app.unusableDefaultDevices()).To(BeEmpty(),
			"the app can still open the container runtime's default devices")
	}
	evetest.Checkpoint("serial-passed-through")

	// Phase 4: the flash drive reaches a native app as a readable disk. (In a
	// shim VM, storage is TestUSBFlashDriveHotplug's subject.)
	if native {
		device.AttachUSBStorage(containerFlashDriveID, flashDriveSize)
		t.Eventually(app.blockDisk(containerFlashDriveID), usbEnumerationTimeout,
			usbEnumerationInterval).Should(matchers.SatisfyPredicate(
			"the app has a disk node for the drive and reads its first sector",
			func(d blockDisk) bool { return d.Node != "" && d.Read }))
		evetest.Checkpoint("flash-drive-passed-through")
	}

	// Phase 5: unplugged devices leave the app, which runs on.
	device.DetachUSBSerial(serialAdapterID)
	if native {
		device.DetachUSBStorage(containerFlashDriveID)
	}
	t.Eventually(app.serialPort(serialAdapterID), usbEnumerationTimeout,
		usbEnumerationInterval).Should(matchers.SatisfyPredicate(
		"the adapter's link is gone from the app",
		func(p serialPort) bool { return p.Link == "" }))
	if native {
		t.Eventually(app.blockDisk(containerFlashDriveID), usbEnumerationTimeout,
			usbEnumerationInterval).Should(matchers.SatisfyPredicate(
			"the drive's disk node is gone from the app",
			func(d blockDisk) bool { return d.Node == "" }))
		t.Expect(app.canOpenCharDevice(port.Major, port.Minor)).To(BeFalse(),
			"a node for the unplugged adapter's device numbers does not open")
		t.Expect(app.unusableDefaultDevices()).To(BeEmpty(),
			"the app can still open the container runtime's default devices")
	}
	t.Expect(app.bootMarker()).To(Equal(marker), "the app did not restart")
	evetest.Checkpoint("devices-unplugged")

	// Phase 6: re-plugged behind a hub, on a port path nobody claimed, the
	// adapter reaches the running app again.
	device.AttachUSBHub(serialHubID, "")
	device.AttachUSBSerialBehind(serialHubID, serialAdapterID)
	t.Eventually(app.serialPort(serialAdapterID), usbEnumerationTimeout,
		usbEnumerationInterval).Should(usableSerialPort)
	t.Expect(app.bootMarker()).To(Equal(marker), "the app did not restart")
	evetest.Checkpoint("serial-replugged-elsewhere")

	// Phase 7: a native app can't use a device it wasn't given.
	if native {
		t.Expect(app.canOpenCharDevice(unassignedCharMajor, unassignedCharMinor)).To(BeFalse(),
			fmt.Sprintf("a node for an unassigned device (%d:%d) does not open",
				unassignedCharMajor, unassignedCharMinor))
		evetest.Checkpoint("unassigned-device-refused")
	}

	// Leave the device as found: no adapter, no hub, no app, no model entries.
	device.DetachUSBSerial(serialAdapterID)
	device.DetachUSBHub(serialHubID)
	deleteAppAndWait(t, device, devConfig, appUUID)
	devConfig.DeletePhysicalIO(usbSerialLabel)
	devConfig.DeletePhysicalIO(usbCtrFlashLabel)
	device.ApplyConfig(devConfig, true, false)
}
