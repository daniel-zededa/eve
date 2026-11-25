// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devwait

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsCharDevice(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "null")
	if err := os.Symlink("/dev/null", link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/dev/null", true},
		{link, true},
		{file, false},
		{dir, false},
		{filepath.Join(dir, "missing"), false},
	} {
		if got := IsCharDevice(tc.path); got != tc.want {
			t.Errorf("IsCharDevice(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestForCharDeviceAppears(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "dio")
	go func() {
		time.Sleep(1500 * time.Millisecond)
		_ = os.Symlink("/dev/null", link)
	}()
	logged := false
	err := ForCharDevice(link, 10*time.Second, func(string, ...interface{}) { logged = true })
	if err != nil {
		t.Fatalf("ForCharDevice: %v", err)
	}
	if !logged {
		t.Error("no log line for the wait")
	}
}

func TestForCharDeviceTimeout(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ForCharDevice(filepath.Join(dir, "missing"), 1500*time.Millisecond, nil); err == nil {
		t.Error("missing path: no error")
	}
	if err := ForCharDevice(file, 1500*time.Millisecond, nil); err == nil {
		t.Error("regular file: no error")
	}
	if err := ForCharDevice("/dev/null", time.Second, nil); err != nil {
		t.Errorf("/dev/null: %v", err)
	}
}
