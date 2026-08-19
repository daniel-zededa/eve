// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckBlockedDirs(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		allowed bool
	}{
		{"plain blocked dir", "/persist/vault", false},
		{"file under blocked dir", "/persist/vault/protector.key", false},
		{"other blocked dirs", "/run/domainmgr/cloudinit/x", false},
		{"kube blocked dir", "/run/.kube/k3s/user.yaml", false},
		{"relative blocked dir", "persist/vault/x", false},

		// normalization: these all name a blocked file
		{"double slash", "/persist//vault/x", false},
		{"dot segment", "/persist/./vault/x", false},
		{"leading double slash", "//persist/vault/x", false},
		{"parent traversal", "/persist/status/../vault/x", false},
		{"trailing slash", "/persist/vault/", false},

		// the same file through the container's host-root mounts
		{"hostfs bind", "/hostfs/persist/vault/x", false},
		{"hostfs with double slash", "/hostfs//persist/vault/x", false},
		{"procfs root", "/proc/1/root/persist/vault/x", false},
		{"host procfs bind", "/host/proc/1/root/persist/vault/x", false},

		// must stay readable: a longer name that merely shares a prefix
		{"sibling of blocked dir", "/persist/vaulted/x", true},
		{"prefix is not a segment", "/persist/vaultfoo", true},
		{"unrelated persist path", "/persist/status/zedagent", true},
		{"unrelated run path", "/run/zedrouter/AppNetworkStatus", true},
		{"hostfs unrelated", "/hostfs/persist/log", true},
		{"proc without root", "/proc/1/cmdline", true},
		{"literal hostfs dir", "/hostfs", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkBlockedDirs(tc.path); got != tc.allowed {
				t.Errorf("checkBlockedDirs(%q) = %v, want %v", tc.path, got, tc.allowed)
			}
		})
	}
}

// TestCheckBlockedDirsSymlink verifies that a symlink pointing into a blocked
// directory is blocked under its own name too.
func TestCheckBlockedDirsSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "shortcut")
	if err := os.Symlink("/persist/vault", link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	// EvalSymlinks only resolves an existing target, so this asserts nothing
	// on a host without /persist/vault.
	if _, err := os.Stat("/persist/vault"); err != nil {
		t.Skip("no /persist/vault on this host")
	}
	if checkBlockedDirs(link) {
		t.Errorf("checkBlockedDirs(%q) = true, want false", link)
	}
}
