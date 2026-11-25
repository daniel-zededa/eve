// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package devwait waits for device nodes that appear some time after boot.
//
// Some devices assigned to applications are created late: a GPIO chip that a
// boot script assembles once its source pin controller has probed, a USB
// serial adapter, a device a driver registers after loading firmware. An
// application that starts before then must not start without the device, and
// must not fail for good either: waiting a bounded time covers the boot race,
// and failing after that lets the caller report it and retry later.
package devwait

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultTimeout is how long application start waits for an assigned device
// node. It covers devices created late in boot; a device still missing after
// that is reported as an error.
const DefaultTimeout = 2 * time.Minute

// pollInterval is how often the path is checked again.
const pollInterval = time.Second

// IsCharDevice reports whether path, after following symlinks, is a character
// device.
func IsCharDevice(path string) bool {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFCHR
}

// ForCharDevice waits up to timeout for path to exist and resolve to a
// character device. It returns at once if it already does. logf, if not nil,
// is called once when waiting starts.
func ForCharDevice(path string, timeout time.Duration, logf func(format string, args ...interface{})) error {
	if IsCharDevice(path) {
		return nil
	}
	if logf != nil {
		logf("waiting up to %v for device %s", timeout, path)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)
		if IsCharDevice(path) {
			return nil
		}
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("device %s not available after %v: %w", path, timeout, err)
	}
	return fmt.Errorf("%s is not a character device (waited %v)", path, timeout)
}
