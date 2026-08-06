// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
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

// captureSlog swaps the default logger for the duration of fn.
func captureSlog(t *testing.T, fn func()) string {
	t.Helper()

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(old)

	fn()
	return buf.String()
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

	out := captureSlog(t, func() {
		if err := reload(reloadDeps{configPath: path, runtimeCfg: rc, pool: &countingPool{}}); err != nil {
			t.Fatalf("reload: %v", err)
		}
	})

	if !strings.Contains(out, "require a restart") {
		t.Errorf("no warning about unapplied settings; operator would believe the CA rotated.\nlogs: %s", out)
	}
	if !strings.Contains(out, "mitm_cert_path") {
		t.Errorf("warning does not name the ignored field.\nlogs: %s", out)
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

	out := captureSlog(t, func() {
		if err := reload(reloadDeps{configPath: path, runtimeCfg: rc, pool: &countingPool{}}); err != nil {
			t.Fatalf("reload: %v", err)
		}
	})

	if strings.Contains(out, "require a restart") {
		t.Errorf("warned about a policy-only change.\nlogs: %s", out)
	}
}

// TestReloadRotatesLogFiles covers the blocked-log rotation path: SIGHUP is the
// documented way to rotate, so the new file must be in use afterwards.
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
	if rc.GetBlockedLogger() == nil {
		t.Fatal("blocked logger was not installed")
	}

	// Reloading again must swap in a fresh handle without error, which is what
	// rotation depends on.
	if err := reload(reloadDeps{configPath: path, runtimeCfg: rc, pool: &countingPool{}}); err != nil {
		t.Fatalf("second reload (rotation): %v", err)
	}
	if rc.GetBlockedLogger() == nil {
		t.Fatal("blocked logger was lost across rotation")
	}
	rc.CloseBlockedLog()
}
