// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// What usbmanager could not pass through to a domain shows as a warning on
// the USB device adapters that domain uses, not on others, and goes away
// when usbmanager clears it, also after the adapter went to another app.
func TestSetUSBPassthroughErrors(t *testing.T) {
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	appA := uuid.Must(uuid.FromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8"))
	appB := uuid.Must(uuid.FromString("6ba7b811-9dad-11d1-80b4-00c04fd430c8"))
	domainA := appA.String() + ".1.1"
	aa := &types.AssignableAdapters{IoBundleList: []types.IoBundle{
		{Phylabel: "VIDEO", Type: types.IoUSBDevice, UsedByUUID: appA},
		{Phylabel: "SERIAL", Type: types.IoUSBDevice, UsedByUUID: appB},
		{Phylabel: "eth1", Type: types.IoNetEth, UsedByUUID: appA},
	}}
	ctx := &domainContext{
		assignableAdapters:    aa,
		pubAssignableAdapters: testPublication(t, ps, types.AssignableAdapters{}),
	}
	errorOf := func(phylabel string) string {
		for _, ib := range aa.IoBundleList {
			if ib.Phylabel == phylabel {
				return ib.Error.String()
			}
		}
		t.Fatalf("no adapter %s", phylabel)
		return ""
	}

	setUSBPassthroughErrors(ctx, domainA, "device cgroup: permission denied")
	if got := errorOf("VIDEO"); !strings.Contains(got, domainA) ||
		!strings.Contains(got, "device cgroup: permission denied") {
		t.Fatalf("VIDEO error %q", got)
	}
	if !aa.IoBundleList[0].Error.IsOnlyWarnings() {
		t.Error("reported as a hard error, want a warning")
	}
	if got := errorOf("SERIAL") + errorOf("eth1"); got != "" {
		t.Fatalf("other adapters got %q", got)
	}

	// the same report again changes nothing; a new one replaces it
	setUSBPassthroughErrors(ctx, domainA, "device cgroup: permission denied")
	setUSBPassthroughErrors(ctx, domainA, "container is stopped")
	if got := errorOf("VIDEO"); strings.Contains(got, "permission denied") ||
		!strings.Contains(got, "container is stopped") {
		t.Fatalf("VIDEO error %q after a new report", got)
	}

	// cleared also when the adapter went to another app meanwhile
	aa.IoBundleList[0].UsedByUUID = appB
	setUSBPassthroughErrors(ctx, domainA, "")
	if got := errorOf("VIDEO"); got != "" {
		t.Fatalf("VIDEO error %q after it was cleared", got)
	}
}
