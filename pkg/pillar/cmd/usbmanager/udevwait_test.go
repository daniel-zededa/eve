// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package usbmanager

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	devconfig "github.com/opencontainers/cgroups/devices/config"
)

// A node plugged in while the container runs gets the mode udev gives it on
// the host, so the copy waits until udev has handled the device, and no
// longer than udevWait.
func TestWaitForUdev(t *testing.T) {
	oldDir, oldWait := udevDataDir, udevWait
	defer func() { udevDataDir, udevWait = oldDir, oldWait }()
	udevDataDir, udevWait = t.TempDir(), 300*time.Millisecond
	n := devNode{name: "video2", devType: devconfig.CharDevice, major: 81, minor: 2}

	entry := filepath.Join(udevDataDir, "c81:2")
	written := make(chan error, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		written <- os.WriteFile(entry, nil, 0o644)
	}()
	start := time.Now()
	waitForUdev(n)
	if d := time.Since(start); d < 100*time.Millisecond || d > 250*time.Millisecond {
		t.Errorf("waited %v for udev's entry written after 100ms", d)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}

	start = time.Now()
	waitForUdev(devNode{name: "video3", devType: devconfig.CharDevice, major: 81, minor: 3})
	if d := time.Since(start); d < 300*time.Millisecond || d > 450*time.Millisecond {
		t.Errorf("waited %v for an entry that never comes, want about udevWait", d)
	}

	udevDataDir = filepath.Join(udevDataDir, "absent")
	start = time.Now()
	waitForUdev(n)
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("waited %v without udev", d)
	}
}
