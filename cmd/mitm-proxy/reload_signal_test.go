// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

//go:build unix

// SIGHUP does not exist on Windows, so the signal-driven reload test lives
// behind a build tag rather than failing to compile on a platform that cannot
// deliver the signal at all.

package main

import (
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"go-egress-proxy/internal/metrics"
)

// TestReloadFailureCountsOnce guards against double-counting.
//
// LoadConfig used to increment ConfigLoadErrors itself, and watchSIGHUP
// increments it again for any reload error — so a malformed-YAML SIGHUP, the
// common case, counted twice while a later failure (bad trace regex, unopenable
// log, bad CA source) counted once. A counter that weights failures by which
// stage they occurred in cannot be read as reload health.
func TestReloadFailureCountsOnce(t *testing.T) {
	dir := t.TempDir()
	rc, certPath, keyPath := newLoadedRuntime(t, dir)

	good := writeConfig(t, dir, "good.yaml", strings.NewReplacer("CERT", certPath, "KEY", keyPath).
		Replace(baseConfig("ALLOW", "x.example.com")))
	bad := writeConfig(t, dir, "bad.yaml", "proxy: [not valid yaml")

	run := func(path string) {
		ch := make(chan os.Signal, 1)
		ch <- syscall.SIGHUP
		close(ch)
		watchSIGHUP(ch, reloadDeps{configPath: path, runtimeCfg: rc, pool: &countingPool{}})
	}

	errsBefore := testutil.ToFloat64(metrics.ConfigLoadErrors)
	run(bad)
	if delta := testutil.ToFloat64(metrics.ConfigLoadErrors) - errsBefore; delta != 1 {
		t.Errorf("ConfigLoadErrors moved by %v on one failed reload, want 1", delta)
	}

	okBefore := testutil.ToFloat64(metrics.ConfigReloads)
	run(good)
	if delta := testutil.ToFloat64(metrics.ConfigReloads) - okBefore; delta != 1 {
		t.Errorf("ConfigReloads moved by %v on one successful reload, want 1", delta)
	}
	// A successful reload must not also record an error.
	if delta := testutil.ToFloat64(metrics.ConfigLoadErrors) - errsBefore; delta != 1 {
		t.Errorf("ConfigLoadErrors moved by %v after one failure and one success, want 1", delta)
	}
}
