// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// setupProxyPolicyTest points the address lists and the policies at a known
// device: one device address, one app with VNC display :1 enabled.
func setupProxyPolicyTest(t *testing.T, dev, app, ext bool) {
	t.Helper()
	ensureTestLog()

	origDev, origApp := devIntfIPs, appIntfIPs
	origDevPol, origAppPol, origExtPol := devPolicy, appPolicy, extPolicy
	origStatus := evStatus

	devIntfIPs = []string{"192.168.1.10", "0.0.0.0", "127.0.0.1", "::", "::1", "localhost"}
	appIntfIPs = []appIPvnc{
		{ipAddr: "10.1.0.102", appName: "app1", vncEnable: true, vncPort: 1},
		{ipAddr: "10.1.0.103", appName: "app2", vncEnable: false, vncPort: 2},
	}
	devPolicy = types.EvDevPolicy{Enabled: dev}
	appPolicy = types.EvAppPolicy{Enabled: app}
	extPolicy = types.EvExtPolicy{Enabled: ext}
	evStatus = types.EdgeviewStatus{}

	t.Cleanup(func() {
		devIntfIPs, appIntfIPs = origDev, origApp
		devPolicy, appPolicy, extPolicy = origDevPol, origAppPol, origExtPol
		evStatus = origStatus
	})
}

// TestCheckAndLogProxySession covers the classification of a 'tcp/proxy'
// CONNECT destination. A destination on the device must be governed by the
// device policy rather than falling through to the external policy.
func TestCheckAndLogProxySession(t *testing.T) {
	cases := []struct {
		name          string
		host          string
		dev, app, ext bool
		wantOK        bool
		wantErr       string
	}{
		{
			name: "device loopback needs the device policy",
			host: "127.0.0.1:22",
			ext:  true, // external allowed, device is not
			// would have been allowed as '(ext)' before
			wantErr: devPolicyErr,
		},
		{
			name:   "device loopback with the device policy",
			host:   "127.0.0.1:22",
			dev:    true,
			wantOK: true,
		},
		{
			name:    "device IPv6 loopback needs the device policy",
			host:    "[::1]:22",
			ext:     true,
			wantErr: devPolicyErr,
		},
		{
			name:    "device interface address needs the device policy",
			host:    "192.168.1.10:6443",
			ext:     true,
			wantErr: devPolicyErr,
		},
		{
			name:   "app address with the app policy",
			host:   "10.1.0.102:8080",
			app:    true,
			wantOK: true,
		},
		{
			name:    "app address without the app policy",
			host:    "10.1.0.102:8080",
			ext:     true,
			wantErr: appPolicyErr,
		},
		{
			name:    "app address without VNC enabled",
			host:    "10.1.0.103:8080",
			app:     true,
			wantErr: vncPolicyErr,
		},
		{
			// the console port wins over the device address it listens on,
			// the same way checkIPportPolicy orders the two
			name:   "app console port is an app destination",
			host:   "127.0.0.1:5901",
			app:    true,
			wantOK: true,
		},
		{
			name:    "app console port without the app policy",
			host:    "127.0.0.1:5901",
			dev:     true,
			ext:     true,
			wantErr: appPolicyErr,
		},
		{
			name:   "external address with the external policy",
			host:   "93.184.216.34:443",
			ext:    true,
			wantOK: true,
		},
		{
			name:    "external address without the external policy",
			host:    "93.184.216.34:443",
			dev:     true,
			app:     true,
			wantErr: extPolicyErr,
		},
		{
			name:    "no port still classifies the address",
			host:    "192.168.1.10",
			ext:     true,
			wantErr: devPolicyErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupProxyPolicyTest(t, tc.dev, tc.app, tc.ext)

			ok, errmsg := checkAndLogProxySession(tc.host)
			if ok != tc.wantOK {
				t.Errorf("checkAndLogProxySession(%q) = %v (%s), want %v",
					tc.host, ok, errmsg, tc.wantOK)
			}
			if errmsg != tc.wantErr {
				t.Errorf("checkAndLogProxySession(%q) errmsg = %q, want %q",
					tc.host, errmsg, tc.wantErr)
			}
		})
	}
}

// TestCheckAndLogProxySessionName verifies that a name that cannot be resolved
// is still classified, and lands on the external policy.
func TestCheckAndLogProxySessionName(t *testing.T) {
	setupProxyPolicyTest(t, false, false, true)

	// '.invalid' never resolves (RFC 2606)
	if ok, errmsg := checkAndLogProxySession("nothing.invalid:443"); !ok {
		t.Errorf("checkAndLogProxySession(unresolvable name) = false (%s), want true", errmsg)
	}
}

func TestSplitProxyHostPort(t *testing.T) {
	cases := []struct {
		host     string
		wantHost string
		wantPort string
	}{
		{"127.0.0.1:22", "127.0.0.1", "22"},
		{"example.com:443", "example.com", "443"},
		{"[::1]:22", "::1", "22"},
		{"[fd00::1]:8080", "fd00::1", "8080"},
		{"example.com", "example.com", ""},
		{"[::1]", "::1", ""},
		{"192.168.1.10", "192.168.1.10", ""},
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			gotHost, gotPort := splitProxyHostPort(tc.host)
			if gotHost != tc.wantHost || gotPort != tc.wantPort {
				t.Errorf("splitProxyHostPort(%q) = (%q, %q), want (%q, %q)",
					tc.host, gotHost, gotPort, tc.wantHost, tc.wantPort)
			}
		})
	}
}
