// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"
)

// TestPreStopGrace covers the parsing, defaulting and rejection paths.
//
// The value decides how long the proxy keeps serving after failing readiness,
// so a silently-misread override either strands traffic (too short) or delays
// every shutdown (too long). Both failure modes are quiet.
func TestPreStopGrace(t *testing.T) {
	tests := []struct {
		name string
		set  bool
		env  string
		want time.Duration
	}{
		{"unset uses the default", false, "", defaultPreStopGrace},
		{"empty uses the default", true, "", defaultPreStopGrace},
		{"valid duration", true, "3s", 3 * time.Second},
		{"zero disables the wait", true, "0", 0},
		{"zero with unit disables the wait", true, "0s", 0},
		{"sub-second is honored", true, "250ms", 250 * time.Millisecond},
		{"unparseable falls back", true, "soon", defaultPreStopGrace},
		{"bare number falls back", true, "10", defaultPreStopGrace},
		{"negative falls back", true, "-5s", defaultPreStopGrace},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv("PROXY_PRESTOP_GRACE", tt.env)
			}
			if got := preStopGrace(); got != tt.want {
				t.Errorf("preStopGrace() = %v, want %v", got, tt.want)
			}
		})
	}
}
