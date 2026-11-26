// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package usbmanager

// Reconciling native containers with the USB devices passed through to them.
//
// The controller decides, under its lock, which USB devices a native
// container should have (containerWants) and queues the container. Making
// it so -- asking containerd, waiting for udev, creating nodes, replacing the
// device cgroup filter -- takes time and is done by one worker goroutine,
// outside the lock, so that a slow device never holds up usbmanager for the
// other domains.
//
// A reconcile always rebuilds the container's device filter from scratch,
// from its OCI spec and runc's default devices plus the nodes of the devices
// it should have now, and removes the nodes and links it no longer should
// have. What was applied is also kept in /run/usbmanager, which outlives a
// restart of usbmanager but not a reboot (and so not the containers): after a
// restart, a container that had devices is reconciled again straight away,
// so a device unplugged meanwhile loses its nodes and its allow rule, and the
// device numbers it had can't let the container use whatever device gets
// them next. A periodic resync catches a container that was recreated (its
// init PID changed) without the domain leaving RUNNING, which would have
// given it a fresh device filter from its spec and an empty /dev.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	// appliedStateDir keeps what was applied to each native container across
	// restarts of usbmanager
	appliedStateDir = "/run/usbmanager/containers"
	// containerResyncInterval is how often containers with devices are
	// reconciled even without an event
	containerResyncInterval = 30 * time.Second
)

// containerQueue holds the names of containers to reconcile. Adding one is
// cheap and never blocks, so the controller can do it under its lock.
type containerQueue struct {
	sync.Mutex
	pending map[string]bool
	wake    chan struct{}
}

func newContainerQueue() *containerQueue {
	return &containerQueue{pending: make(map[string]bool), wake: make(chan struct{}, 1)}
}

func (q *containerQueue) add(containerName string) {
	q.Lock()
	q.pending[containerName] = true
	q.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// take returns the queued names, sorted, and empties the queue
func (q *containerQueue) take() []string {
	q.Lock()
	defer q.Unlock()
	names := make([]string, 0, len(q.pending))
	for name := range q.pending {
		names = append(names, name)
	}
	q.pending = make(map[string]bool)
	sort.Strings(names)
	return names
}

// appliedContainer is what a native container was given, as last applied
type appliedContainer struct {
	pid  int
	devs map[string]containerDevices // by USB device
	// staleNames are nodes and links, relative to its /dev, that the
	// container was given before usbmanager restarted
	staleNames []string
}

// appliedRecord is appliedContainer as kept in appliedStateDir
type appliedRecord struct {
	PID   int
	Names []string // nodes and links given, relative to /dev
}

func appliedRecordPath(containerName string) string {
	return filepath.Join(appliedStateDir, containerName+".json")
}

func readAppliedRecord(containerName string) (appliedRecord, bool) {
	var rec appliedRecord
	data, err := os.ReadFile(appliedRecordPath(containerName))
	if err != nil {
		return rec, false
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		log.Warnf("usb passthrough: ignoring %s: %v", appliedRecordPath(containerName), err)
		return rec, false
	}
	return rec, true
}

func writeAppliedRecord(containerName string, rec appliedRecord) error {
	if err := os.MkdirAll(appliedStateDir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp := appliedRecordPath(containerName) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, appliedRecordPath(containerName))
}

func removeAppliedRecord(containerName string) {
	if err := os.Remove(appliedRecordPath(containerName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Warnf("usb passthrough: %v", err)
	}
}

func (a *appliedContainer) names() []string {
	var names []string
	for _, devs := range a.devs {
		for _, n := range devs.nodes {
			names = append(names, n.name)
		}
		for _, l := range devs.links {
			names = append(names, l.name)
		}
	}
	sort.Strings(names)
	return names
}

func (a *appliedContainer) nodes() []devNode {
	var nodes []devNode
	for _, devs := range a.devs {
		nodes = append(nodes, devs.nodes...)
	}
	return nodes
}

// sameDeviceNumbers tells whether two node lists allow the same devices
func sameDeviceNumbers(a, b []devNode) bool {
	set := func(nodes []devNode) string {
		keys := make([]string, 0, len(nodes))
		for _, n := range nodes {
			keys = append(keys, fmt.Sprintf("%c%d:%d", n.devType, n.major, n.minor))
		}
		sort.Strings(keys)
		return strings.Join(keys, ",")
	}
	return set(a) == set(b)
}

// wantContainer records, under the controller's lock, that a native
// container is running and may get USB devices, and queues it if it had
// devices before usbmanager restarted.
func (uc *usbmanagerController) wantContainer(containerName string) {
	if uc.containerWants[containerName] == nil {
		uc.containerWants[containerName] = make(map[string]string)
	}
	if _, ok := readAppliedRecord(containerName); ok {
		uc.containerQueue.add(containerName)
	}
}

// forgetContainer records, under the controller's lock, that a native
// container stopped running.
func (uc *usbmanagerController) forgetContainer(containerName string) {
	delete(uc.containerWants, containerName)
	uc.containerQueue.add(containerName)
}

// startContainerReconciler runs the worker that reconciles queued containers
// until stop is closed.
func (uc *usbmanagerController) startContainerReconciler(stop <-chan struct{}) {
	go func() {
		resync := time.NewTicker(containerResyncInterval)
		defer resync.Stop()
		for {
			select {
			case <-stop:
				return
			case <-uc.containerQueue.wake:
			case <-resync.C:
				uc.queueContainersWithDevices()
			}
			uc.reconcileQueuedContainers()
		}
	}()
}

// queueContainersWithDevices queues every container that has or should have
// USB devices, to notice ones that were recreated meanwhile.
func (uc *usbmanagerController) queueContainersWithDevices() {
	uc.Lock()
	for name, wants := range uc.containerWants {
		if len(wants) > 0 {
			uc.containerQueue.add(name)
		}
	}
	uc.Unlock()
	for name := range uc.applied {
		uc.containerQueue.add(name)
	}
}

func (uc *usbmanagerController) reconcileQueuedContainers() {
	for _, name := range uc.containerQueue.take() {
		uc.reconcileContainer(name)
	}
}

// reconcileContainer gives a native container exactly the nodes, links and
// device cgroup rules of the USB devices it should have now. It is called
// by the worker only, without the controller's lock.
func (uc *usbmanagerController) reconcileContainer(containerName string) {
	uc.Lock()
	wantDirs, running := uc.containerWants[containerName]
	sysDirs := make(map[string]string, len(wantDirs))
	for key, dir := range wantDirs {
		sysDirs[key] = dir
	}
	uc.Unlock()

	applied := uc.applied[containerName]
	if !running {
		// gone, with its /dev and its cgroup
		delete(uc.applied, containerName)
		removeAppliedRecord(containerName)
		uc.reportContainerPassthrough(containerName, nil)
		return
	}
	rec, hadRecord := readAppliedRecord(containerName)
	if len(sysDirs) == 0 && applied == nil && !hadRecord {
		// never given anything: leave it alone
		return
	}

	state, err := loadContainerState(containerName)
	if err != nil {
		uc.reportContainerPassthrough(containerName, []error{err})
		return
	}
	filterUpToDate := applied != nil && applied.pid == state.pid
	if !filterUpToDate {
		// first reconcile since usbmanager started, or the container was
		// recreated: rebuild everything
		fresh := &appliedContainer{pid: state.pid, devs: make(map[string]containerDevices)}
		if applied == nil && hadRecord && rec.PID == state.pid {
			fresh.staleNames = rec.Names
		}
		applied = fresh
	}

	// what the devices have now; udev on the host sets a node's mode and
	// owner and adds its links (e.g. /dev/serial/by-id) after the kernel
	// event that brought us here, and adding a link raises no event of its
	// own, so wait for udev first, then copy both
	want := make(map[string]containerDevices, len(sysDirs))
	wantNames := make(map[string]bool)
	var wantNodes []devNode
	for key, sysDir := range sysDirs {
		nodes := usbDeviceNodes(sysDir)
		for _, n := range nodes {
			waitForUdev(n)
		}
		devs := containerDevices{nodes: nodes, links: nodeLinks(nodes)}
		want[key] = devs
		wantNodes = append(wantNodes, nodes...)
		for _, n := range devs.nodes {
			wantNames[n.name] = true
		}
		for _, l := range devs.links {
			wantNames[l.name] = true
		}
	}

	var errs []error
	devFD, err := containerDevDir(state.pid)
	if err != nil {
		uc.reportContainerPassthrough(containerName, []error{err})
		return
	}
	defer unix.Close(devFD)

	// take away first: what it no longer should have, and what it was
	// given before a restart of usbmanager and should not have now
	for _, name := range append(applied.names(), applied.staleNames...) {
		if !wantNames[name] {
			removeEntry(devFD, name)
		}
	}
	if !filterUpToDate || !sameDeviceNumbers(applied.nodes(), wantNodes) {
		if err := setDeviceFilter(state.cgroupDir, deviceRules(state, wantNodes)); err != nil {
			errs = append(errs, fmt.Errorf("device cgroup: %w", err))
			// try again with the next event or resync
			applied.pid = 0
		}
	}
	for _, devs := range want {
		for _, n := range devs.nodes {
			if err := createNode(devFD, n); err != nil {
				errs = append(errs, err)
			}
		}
		for _, l := range devs.links {
			if err := createLink(devFD, l); err != nil {
				errs = append(errs, err)
			}
		}
	}
	applied.devs = want
	applied.staleNames = nil

	if len(want) == 0 && applied.pid != 0 {
		// nothing passed through any more and the filter is the container's
		// own again
		delete(uc.applied, containerName)
		removeAppliedRecord(containerName)
	} else {
		uc.applied[containerName] = applied
		if err := writeAppliedRecord(containerName,
			appliedRecord{PID: state.pid, Names: applied.names()}); err != nil {
			errs = append(errs, err)
		}
	}
	log.Noticef("usb passthrough to container %s: %d devices, nodes and links %v",
		containerName, len(want), applied.names())
	uc.reportContainerPassthrough(containerName, errs)
}

// reportContainerPassthrough publishes what went wrong passing devices
// through to a container, or that nothing did, once per change.
func (uc *usbmanagerController) reportContainerPassthrough(containerName string, errs []error) {
	msgs := make([]string, 0, len(errs))
	for _, err := range errs {
		msgs = append(msgs, err.Error())
		log.Warnf("usb passthrough to container %s: %v", containerName, err)
	}
	msg := strings.Join(msgs, "; ")
	if uc.reportedErrors[containerName] == msg {
		return
	}
	if msg == "" {
		delete(uc.reportedErrors, containerName)
	} else {
		uc.reportedErrors[containerName] = msg
	}
	if uc.publishPassthroughError != nil {
		uc.publishPassthroughError(containerName, msg)
	}
}
