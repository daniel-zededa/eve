// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

// GPIO chips for KVM domains, through virtio-gpio.
//
// An I/O adapter of type "other" that names a host GPIO chip is given to the
// domain as a virtio-gpio device. The chip is named the way EVE names any
// device for an "other" adapter, by its path in phyaddr Ifname, which is also
// what gives it to containers (containerd/oci.go): /dev/gpio/<name> (made by
// pkg/dom0-ztools 008-gpio-expose) or /dev/gpiochipN. The cbattr "gpiochip"
// may name it instead. QEMU has no virtio-gpio backend of its own; it has the
// vhost-user front end (vhost-user-gpio-pci), and the back end is
// vhost-device-gpio (rust-vmm), which drives the host chip through the GPIO
// character device. Lines, directions, values and edge interrupts all reach
// the guest, where the gpio-virtio driver presents a regular gpiochip.
//
// vhost-device-gpio runs in the domain's QEMU container: the eve-vhost-gpio
// launcher in pkg/qemu starts it, waits for its sockets and then execs QEMU,
// so it lives and dies with the domain. One daemon serves all the domain's
// chips, one socket each.
//
// vhost-user back ends access guest memory directly, so a domain with a GPIO
// chip gets its RAM from a shareable memfd memory backend instead of anonymous
// memory.
//
// GPIO chips can appear late in boot (008-gpio-expose waits for its source
// pin controller), so starting a domain waits for its chips, up to
// devwait.DefaultTimeout. A chip still missing then fails the start, which
// domainmgr reports and retries.

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/devwait"
	"github.com/sirupsen/logrus"
)

const (
	// cbattr key of an "other" I/O adapter naming the host GPIO chip
	gpioChipCbattr = "gpiochip"
	// in the pkg/qemu service rootfs
	vhostGpioLauncher = "/usr/bin/eve-vhost-gpio"
)

const qemuGpioTemplate = `
[chardev "vhost-gpio{{.ID}}"]
  backend = "socket"
  path = "{{.Socket}}"

[device "gpio{{.ID}}"]
  driver = "vhost-user-gpio-pci"
  chardev = "vhost-gpio{{.ID}}"
`

// gpioAssignment is one host GPIO chip given to a domain
type gpioAssignment struct {
	ID      int    // index among the domain's chips; also the socket suffix
	Adapter string // logical label of the I/O adapter, for logs
	Chip    string // as configured, e.g. /dev/gpio/dio
	ChipNum int    // N of the /dev/gpiochipN it resolves to
	Socket  string // vhost-user socket
}

// gpioSocketPrefix is what vhost-device-gpio suffixes with 0, 1, ... for the
// sockets of a domain's chips.
func gpioSocketPrefix(domainName string) string {
	return kvmStateDir + domainName + "/vhost-gpio"
}

// gpioChipNum resolves a GPIO chip path (possibly a symlink, like the
// /dev/gpio/<name> ones pkg/dom0-ztools 008-gpio-expose creates) to N in
// /dev/gpiochipN, the form vhost-device-gpio takes.
func gpioChipNum(chip string) (int, error) {
	if !strings.HasPrefix(chip, "/dev/") {
		return 0, fmt.Errorf("GPIO chip %q is not under /dev", chip)
	}
	dev, err := filepath.EvalSymlinks(chip)
	if err != nil {
		return 0, fmt.Errorf("GPIO chip %s: %w", chip, err)
	}
	num, found := strings.CutPrefix(filepath.Base(dev), "gpiochip")
	if !found || filepath.Dir(dev) != "/dev" {
		return 0, fmt.Errorf("GPIO chip %s resolves to %s, not /dev/gpiochipN", chip, dev)
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, fmt.Errorf("GPIO chip %s resolves to %s, not /dev/gpiochipN", chip, dev)
	}
	return n, nil
}

// gpioChipPath returns the GPIO chip an "other" adapter names, if any. The
// cbattr names one explicitly. An Ifname path names one if it is a GPIO chip
// path: /dev/gpio/<name> or /dev/gpiochipN, or a path resolving to the latter
// (other device paths, e.g. /dev/video0, are for containers only).
func gpioChipPath(ib *types.IoBundle) string {
	if chip := ib.Cbattr[gpioChipCbattr]; chip != "" {
		return chip
	}
	path := ib.Ifname
	if strings.HasPrefix(path, "/dev/gpio/") ||
		strings.HasPrefix(path, "/dev/gpiochip") {
		return path
	}
	if strings.HasPrefix(path, "/dev/") {
		if _, err := gpioChipNum(path); err == nil {
			return path
		}
	}
	return ""
}

// gpioAssignments lists the GPIO chips of the domain's I/O adapters, waiting
// for any that isn't there yet. A chip still missing after that is an error:
// starting the domain without it would hide the problem from the user.
func gpioAssignments(domainName string, config types.DomainConfig,
	aa *types.AssignableAdapters) ([]gpioAssignment, error) {
	var gpios []gpioAssignment
	if aa == nil {
		return nil, nil
	}
	seen := make(map[int]bool)
	for _, adapter := range config.IoAdapterList {
		for _, ib := range aa.LookupIoBundleAny(adapter.Name) {
			if ib == nil || ib.Type != types.IoOther ||
				ib.UsedByUUID != config.UUIDandVersion.UUID {
				continue
			}
			chip := gpioChipPath(ib)
			if chip == "" {
				continue
			}
			err := devwait.ForCharDevice(chip, devwait.DefaultTimeout,
				func(format string, args ...interface{}) {
					logrus.Infof("domain %s, I/O adapter %s: "+format,
						append([]interface{}{domainName, ib.Logicallabel}, args...)...)
				})
			if err != nil {
				return nil, fmt.Errorf("I/O adapter %s: %w", ib.Logicallabel, err)
			}
			n, err := gpioChipNum(chip)
			if err != nil {
				return nil, fmt.Errorf("I/O adapter %s: %w", ib.Logicallabel, err)
			}
			if seen[n] {
				continue
			}
			seen[n] = true
			id := len(gpios)
			gpios = append(gpios, gpioAssignment{
				ID:      id,
				Adapter: ib.Logicallabel,
				Chip:    chip,
				ChipNum: n,
				Socket:  fmt.Sprintf("%s%d", gpioSocketPrefix(domainName), id),
			})
		}
	}
	return gpios, nil
}

// gpioLauncherArgs is the command prefix that starts vhost-device-gpio for
// the domain's chips before QEMU:
//
//	eve-vhost-gpio <socket prefix> <N0>[:<N1>...] -- qemu-system-... args
func gpioLauncherArgs(domainName string, gpios []gpioAssignment) []string {
	if len(gpios) == 0 {
		return nil
	}
	nums := make([]string, len(gpios))
	for i, g := range gpios {
		nums[i] = strconv.Itoa(g.ChipNum)
		logrus.Infof("domain %s: GPIO chip %s (/dev/gpiochip%d) of adapter %s via virtio-gpio",
			domainName, g.Chip, g.ChipNum, g.Adapter)
	}
	return []string{vhostGpioLauncher, gpioSocketPrefix(domainName),
		strings.Join(nums, ":"), "--"}
}
