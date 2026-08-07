// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go-egress-proxy/internal/cert"
	"go-egress-proxy/internal/config"
)

// countingPool records Reset() calls so the reload's pool interaction is
// observable without standing up real transports.
type countingPool struct{ resets int }

func (p *countingPool) Reset() { p.resets++ }

// writeConfig writes cfg to a file in dir and returns its path.
func writeConfig(t *testing.T, dir, name, body string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// baseConfig is a minimal valid configuration. extraProxy is inserted inside the
// proxy block -- appending it after the acl block would silently put the key in
// the wrong section, where it is ignored rather than rejected.
func baseConfig(policy, blacklistEntry string, extraProxy ...string) string {
	proxy := `proxy:
  port: "8080"
  metrics_port: "9090"
  default_policy: "` + policy + `"
  mitm_cert_path: "CERT"
  mitm_key_path: "KEY"
`
	for _, line := range extraProxy {
		proxy += "  " + line + "\n"
	}
	return proxy + `acl:
  blacklist:
    - "` + blacklistEntry + `"
`
}

// newLoadedRuntime returns a RuntimeConfig already holding a valid config, as
// the running proxy would have, plus the cert paths used to build it.
func newLoadedRuntime(t *testing.T, dir string) (*config.RuntimeConfig, string, string) {
	t.Helper()

	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := cert.RunGencert([]string{
		"--type", "root", "--cn", "Reload Test CA",
		"--out-cert", certPath, "--out-key", keyPath,
	}); err != nil {
		t.Fatalf("gencert: %v", err)
	}

	body := strings.NewReplacer("CERT", certPath, "KEY", keyPath).
		Replace(baseConfig("BLOCK", "first.example.com"))
	path := writeConfig(t, dir, "initial.yaml", body)

	cfg, acl, rewrites, err := config.LoadAndCompileConfig(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	tlsCfg, err := cert.BuildOutboundTLSConfig(cfg)
	if err != nil {
		t.Fatalf("initial TLS config: %v", err)
	}

	rc := &config.RuntimeConfig{}
	_ = rc.Update(cfg, acl, rewrites, tlsCfg, nil, nil)
	return rc, certPath, keyPath
}

// captureRecords swaps the default logger for the duration of fn and returns
// the emitted records decoded from JSON.
//
// Decoding rather than substring-matching keeps these assertions tied to the
// structure slog actually emits -- level, message, attributes -- instead of to
// incidental formatting or exact wording.
func captureRecords(t *testing.T, fn func()) []map[string]any {
	t.Helper()

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(old)

	fn()

	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v\n%s", err, line)
		}
		records = append(records, rec)
	}
	return records
}

// findRestartWarning returns the fields named by the WARN record listing
// settings a reload cannot apply, and whether such a record was emitted.
func findRestartWarning(records []map[string]any) ([]string, bool) {
	for _, rec := range records {
		if rec["level"] != "WARN" {
			continue
		}
		raw, ok := rec["fields"].([]any)
		if !ok {
			continue
		}
		fields := make([]string, 0, len(raw))
		for _, f := range raw {
			if s, ok := f.(string); ok {
				fields = append(fields, s)
			}
		}
		return fields, true
	}
	return nil, false
}

// TestReloadAppliesNewConfiguration is the happy path: new policy in effect,
// pool reset so connections to previous rewrite targets stop being reused.
func TestReloadAppliesNewConfiguration(t *testing.T) {
	dir := t.TempDir()
	rc, certPath, keyPath := newLoadedRuntime(t, dir)

	body := strings.NewReplacer("CERT", certPath, "KEY", keyPath).
		Replace(baseConfig("ALLOW", "second.example.com"))
	path := writeConfig(t, dir, "updated.yaml", body)

	pool := &countingPool{}
	if err := reload(reloadDeps{configPath: path, runtimeCfg: rc, pool: pool}); err != nil {
		t.Fatalf("reload: %v", err)
	}

	cfg, acl, _, _, _ := rc.Get()
	if cfg.Proxy.DefaultPolicy != "ALLOW" {
		t.Errorf("DefaultPolicy = %q, want ALLOW", cfg.Proxy.DefaultPolicy)
	}
	if !config.Matches("second.example.com", acl.Blacklist) {
		t.Error("new blacklist entry is not in effect")
	}
	if config.Matches("first.example.com", acl.Blacklist) {
		t.Error("previous blacklist entry survived the reload")
	}
	if pool.resets != 1 {
		t.Errorf("pool Reset() called %d times, want 1; stale targets would serve until IdleConnTimeout", pool.resets)
	}
}

// TestReloadKeepsPreviousConfigOnFailure is the property that makes SIGHUP safe
// on a live proxy: a bad edit must not take the running config down with it.
func TestReloadKeepsPreviousConfigOnFailure(t *testing.T) {
	tests := []struct {
		name string
		body func(certPath, keyPath string) string
	}{
		{
			name: "unparseable YAML",
			body: func(string, string) string { return "proxy: [this is not valid" },
		},
		{
			name: "fails validation",
			body: func(c, k string) string {
				return strings.NewReplacer("CERT", c, "KEY", k).
					Replace(baseConfig("NOT-A-POLICY", "x.example.com"))
			},
		},
		{
			name: "invalid trace regex",
			body: func(c, k string) string {
				return strings.NewReplacer("CERT", c, "KEY", k).
					Replace(baseConfig("ALLOW", "x.example.com")) + `trace:
  enabled: true
  rules:
    - host: "~[unclosed"
`
			},
		},
		{
			name: "unloadable CA bundle",
			body: func(c, k string) string {
				return strings.NewReplacer("CERT", c, "KEY", k).
					Replace(baseConfig("ALLOW", "x.example.com", `outgoing_ca_bundle: "/nonexistent/bundle.pem"`))
			},
		},
		{
			name: "trace log directory does not exist",
			body: func(c, k string) string {
				return strings.NewReplacer("CERT", c, "KEY", k).
					Replace(baseConfig("ALLOW", "x.example.com")) + `trace:
  enabled: true
  log_path: "/nonexistent/dir/trace.jsonl"
  rules:
    - host: "*"
`
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			rc, certPath, keyPath := newLoadedRuntime(t, dir)

			before, beforeACL, _, _, beforeTLS := rc.Get()
			path := writeConfig(t, dir, "bad.yaml", tt.body(certPath, keyPath))

			pool := &countingPool{}
			err := reload(reloadDeps{configPath: path, runtimeCfg: rc, pool: pool})
			if err == nil {
				t.Fatal("reload accepted a broken configuration")
			}

			after, afterACL, _, _, afterTLS := rc.Get()
			if after.Proxy.DefaultPolicy != before.Proxy.DefaultPolicy {
				t.Errorf("DefaultPolicy changed to %q on a failed reload", after.Proxy.DefaultPolicy)
			}
			if !config.Matches("first.example.com", afterACL.Blacklist) {
				t.Error("previous blacklist was lost on a failed reload")
			}
			if len(afterACL.Blacklist) != len(beforeACL.Blacklist) {
				t.Error("ACL was mutated by a failed reload")
			}
			if afterTLS != beforeTLS {
				t.Error("outbound TLS config was replaced by a failed reload")
			}
			if pool.resets != 0 {
				t.Errorf("pool Reset() called %d times on a failed reload; connections must not be dropped", pool.resets)
			}
		})
	}
}

// TestReloadWarnsAboutSettingsItCannotApply pins the honesty fix: reporting a
// clean reload while discarding a rotated MITM CA would leave the proxy signing
// with the old CA until restart.
func TestReloadWarnsAboutSettingsItCannotApply(t *testing.T) {
	dir := t.TempDir()
	rc, _, _ := newLoadedRuntime(t, dir)

	// A second CA, as an operator rotating an expiring one would produce.
	newCert := filepath.Join(dir, "new-ca.crt")
	newKey := filepath.Join(dir, "new-ca.key")
	if err := cert.RunGencert([]string{
		"--type", "root", "--cn", "Rotated CA",
		"--out-cert", newCert, "--out-key", newKey,
	}); err != nil {
		t.Fatal(err)
	}

	body := strings.NewReplacer("CERT", newCert, "KEY", newKey).
		Replace(baseConfig("BLOCK", "first.example.com"))
	path := writeConfig(t, dir, "rotated.yaml", body)

	records := captureRecords(t, func() {
		if err := reload(reloadDeps{configPath: path, runtimeCfg: rc, pool: &countingPool{}}); err != nil {
			t.Fatalf("reload: %v", err)
		}
	})

	fields, ok := findRestartWarning(records)
	if !ok {
		t.Fatalf("no WARN record naming unapplied settings; an operator would believe the CA rotated.\nrecords: %v", records)
	}
	if !slices.Contains(fields, "proxy.mitm_cert_path") {
		t.Errorf("warning fields = %v, want it to name proxy.mitm_cert_path", fields)
	}
}

// TestReloadDoesNotWarnForReloadableSettings guards against the warning becoming
// noise operators learn to skip.
func TestReloadDoesNotWarnForReloadableSettings(t *testing.T) {
	dir := t.TempDir()
	rc, certPath, keyPath := newLoadedRuntime(t, dir)

	body := strings.NewReplacer("CERT", certPath, "KEY", keyPath).
		Replace(baseConfig("ALLOW", "changed.example.com"))
	path := writeConfig(t, dir, "policy-only.yaml", body)

	records := captureRecords(t, func() {
		if err := reload(reloadDeps{configPath: path, runtimeCfg: rc, pool: &countingPool{}}); err != nil {
			t.Fatalf("reload: %v", err)
		}
	})

	if fields, ok := findRestartWarning(records); ok {
		t.Errorf("warned about a policy-only change, naming %v", fields)
	}
}

// TestReloadRotatesLogFiles verifies rotation the way logrotate performs it:
// move the file aside, then signal the process to reopen it.
//
// The previous version of this test only asserted the logger was non-nil after a
// second reload, which is true whether or not anything was reopened -- it would
// have passed against a reload that reused the old descriptor and kept writing
// into the moved-away file, which is precisely the bug rotation support exists
// to prevent.
func TestReloadRotatesLogFiles(t *testing.T) {
	dir := t.TempDir()
	rc, certPath, keyPath := newLoadedRuntime(t, dir)

	logPath := filepath.Join(dir, "blocked.log")
	body := strings.NewReplacer("CERT", certPath, "KEY", keyPath).
		Replace(baseConfig("BLOCK", "first.example.com", `blocked_log_path: "`+logPath+`"`))
	path := writeConfig(t, dir, "with-log.yaml", body)

	if err := reload(reloadDeps{configPath: path, runtimeCfg: rc, pool: &countingPool{}}); err != nil {
		t.Fatalf("reload: %v", err)
	}
	t.Cleanup(rc.CloseBlockedLog)

	logger := rc.GetBlockedLogger()
	if logger == nil {
		t.Fatal("blocked logger was not installed")
	}
	logger.Info("before-rotation")

	// logrotate moves the file aside; the descriptor the proxy holds still points
	// at the moved inode.
	rotated := logPath + ".1"
	if err := os.Rename(logPath, rotated); err != nil {
		t.Fatalf("simulate logrotate: %v", err)
	}

	// SIGHUP: the reload must reopen the original path, creating a new file.
	if err := reload(reloadDeps{configPath: path, runtimeCfg: rc, pool: &countingPool{}}); err != nil {
		t.Fatalf("second reload (rotation): %v", err)
	}
	logger = rc.GetBlockedLogger()
	if logger == nil {
		t.Fatal("blocked logger was lost across rotation")
	}
	logger.Info("after-rotation")

	oldContents := readFile(t, rotated)
	newContents := readFile(t, logPath)

	if !strings.Contains(oldContents, "before-rotation") {
		t.Errorf("rotated file lost the pre-rotation entry:\n%s", oldContents)
	}
	if strings.Contains(oldContents, "after-rotation") {
		t.Error("post-rotation entry landed in the moved-aside file; the descriptor was not reopened")
	}
	if !strings.Contains(newContents, "after-rotation") {
		t.Errorf("post-rotation entry did not reach the new file:\n%s", newContents)
	}
	if strings.Contains(newContents, "before-rotation") {
		t.Errorf("new file unexpectedly contains the pre-rotation entry:\n%s", newContents)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestFailingReloadClosesAlreadyOpenedLogs pins the promise in reload()'s doc
// comment: a reload that fails after opening one log file closes it on the way
// out, so a repeatedly failing reload cannot leak a descriptor per attempt.
//
// Every existing failure case left blocked_log_path unset, so newBlockedFile was
// always nil and the cleanup branches always early-returned — deleting all three
// left the suite green.
//
// The assertion is direct rather than inferred from descriptor pressure. An
// rlimit-based version of this test passes even with the cleanup removed,
// because os.File finalizers close leaked descriptors during GC and exhaustion
// never arrives; that makes the leak a latency problem rather than an unbounded
// one, but it also makes it invisible to any exhaustion check.
func TestFailingReloadClosesAlreadyOpenedLogs(t *testing.T) {
	dir := t.TempDir()
	rc, certPath, keyPath := newLoadedRuntime(t, dir)

	body := strings.NewReplacer("CERT", certPath, "KEY", keyPath).
		Replace(baseConfig("ALLOW", "x.example.com",
			`blocked_log_path: "`+filepath.Join(dir, "blocked.log")+`"`))
	path := writeConfig(t, dir, "aborting.yaml", body)

	// A real file, so Close() is observable through its own error behavior.
	opened, err := os.CreateTemp(dir, "blocked-*.log")
	if err != nil {
		t.Fatal(err)
	}

	deps := reloadDeps{
		configPath: path,
		runtimeCfg: rc,
		pool:       &countingPool{},
		openBlockedLog: func(string) (*slog.Logger, *os.File, error) {
			return slog.New(slog.NewJSONHandler(opened, nil)), opened, nil
		},
		openTraceLog: func(string) (*slog.Logger, *os.File, error) {
			return nil, nil, errors.New("simulated trace log failure")
		},
	}

	if err := reload(deps); err == nil {
		t.Fatal("expected the reload to fail on the trace log")
	}

	// Closing twice returns an error only if the first close already happened.
	if err := opened.Close(); err == nil {
		t.Error("the blocked log was still open after the reload aborted; a failing reload leaks a descriptor per attempt")
	}
}

// TestReloadRotatesTraceLog extends rotation coverage to the trace log, which
// the blocked-log test did not reach.
func TestReloadRotatesTraceLog(t *testing.T) {
	dir := t.TempDir()
	rc, certPath, keyPath := newLoadedRuntime(t, dir)

	logPath := filepath.Join(dir, "trace.jsonl")
	body := strings.NewReplacer("CERT", certPath, "KEY", keyPath).
		Replace(baseConfig("ALLOW", "x.example.com")) + `trace:
  enabled: true
  log_path: "` + logPath + `"
  rules:
    - host: "*"
`
	path := writeConfig(t, dir, "traced.yaml", body)

	deps := reloadDeps{configPath: path, runtimeCfg: rc, pool: &countingPool{}}
	if err := reload(deps); err != nil {
		t.Fatalf("reload: %v", err)
	}
	t.Cleanup(rc.CloseTraceLog)

	writeTrace := func(msg string) {
		t.Helper()
		_, logger := rc.GetTrace()
		if logger == nil {
			t.Fatal("trace logger was not installed")
		}
		logger.Info(msg)
	}

	writeTrace("before-rotation")

	rotated := logPath + ".1"
	if err := os.Rename(logPath, rotated); err != nil {
		t.Fatalf("simulate logrotate: %v", err)
	}

	if err := reload(deps); err != nil {
		t.Fatalf("second reload (rotation): %v", err)
	}
	writeTrace("after-rotation")

	oldContents := readFile(t, rotated)
	newContents := readFile(t, logPath)

	if !strings.Contains(oldContents, "before-rotation") {
		t.Errorf("rotated trace file lost the pre-rotation entry:\n%s", oldContents)
	}
	if strings.Contains(oldContents, "after-rotation") {
		t.Error("post-rotation entry landed in the moved-aside trace file; the handle was not reopened")
	}
	if !strings.Contains(newContents, "after-rotation") {
		t.Errorf("post-rotation entry did not reach the new trace file:\n%s", newContents)
	}
}
