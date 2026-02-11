// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package config

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(c *Config)
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with all fields",
			modify: func(c *Config) {
				c.Proxy.Port = "8080"
				c.Proxy.MetricsPort = "9090"
				c.Proxy.DefaultPolicy = "BLOCK"
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
			},
		},
		{
			name: "valid config with defaults applied",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
			},
		},
		{
			name: "invalid default policy",
			modify: func(c *Config) {
				c.Proxy.DefaultPolicy = "INVALID"
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
			},
			wantErr: true,
			errMsg:  "invalid default_policy",
		},
		{
			name: "missing mitm cert path",
			modify: func(c *Config) {
				c.Proxy.MitmKeyPath = "/path/to/key"
			},
			wantErr: true,
			errMsg:  "mitm_cert_path is required",
		},
		{
			name: "missing mitm key path",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
			},
			wantErr: true,
			errMsg:  "mitm_key_path is required",
		},
		{
			name: "valid config with keystore",
			modify: func(c *Config) {
				c.Proxy.MitmKeystorePath = "/path/to/keystore.p12"
				c.Proxy.MitmKeystorePassword = "changeit"
			},
		},
		{
			name: "missing keystore password",
			modify: func(c *Config) {
				c.Proxy.MitmKeystorePath = "/path/to/keystore.p12"
			},
			wantErr: true,
			errMsg:  "mitm_keystore_password is required",
		},
		{
			name: "mutually exclusive cert and keystore",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeystorePath = "/path/to/keystore.p12"
			},
			wantErr: true,
			errMsg:  "mutually exclusive",
		},
		{
			name: "mutually exclusive cert+key and keystore",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Proxy.MitmKeystorePath = "/path/to/keystore.p12"
			},
			wantErr: true,
			errMsg:  "mutually exclusive",
		},
		{
			name:    "no cert or keystore provided",
			modify:  func(c *Config) {},
			wantErr: true,
			errMsg:  "proxy.mitm_cert_path and proxy.mitm_key_path are required",
		},
		{
			name: "invalid rewrite target IP",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "example.com", TargetIP: "not-an-ip"},
				}
			},
			wantErr: true,
			errMsg:  "invalid target_ip",
		},
		{
			name: "valid rewrite rule with target_ip",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "example.com", TargetIP: "10.0.0.1"},
				}
			},
		},
		{
			name: "valid rewrite rule with target_host",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "example.com", TargetHost: "internal.example.com"},
				}
			},
		},
		{
			name: "rewrite missing both target_ip and target_host",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "example.com"},
				}
			},
			wantErr: true,
			errMsg:  "target_ip or target_host is required",
		},
		{
			name: "rewrite with both target_ip and target_host",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "example.com", TargetIP: "10.0.0.1", TargetHost: "internal.example.com"},
				}
			},
			wantErr: true,
			errMsg:  "target_ip and target_host are mutually exclusive",
		},
		{
			name: "valid config with outgoing truststore",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Proxy.OutgoingTruststorePath = "/path/to/truststore.p12"
				c.Proxy.OutgoingTruststorePassword = "changeit"
			},
		},
		{
			name: "missing outgoing truststore password",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Proxy.OutgoingTruststorePath = "/path/to/truststore.p12"
			},
			wantErr: true,
			errMsg:  "outgoing_truststore_password is required",
		},
		{
			name: "valid config with both ca_bundle and truststore",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Proxy.OutgoingCABundle = "/path/to/ca-bundle.pem"
				c.Proxy.OutgoingTruststorePath = "/path/to/truststore.p12"
				c.Proxy.OutgoingTruststorePassword = "changeit"
			},
		},
		{
			name: "valid config with insecure_skip_verify",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Proxy.InsecureSkipVerify = true
			},
		},
		{
			name: "valid rewrite with insecure flag",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "internal.example.com", TargetIP: "10.0.0.1", Insecure: true},
				}
			},
		},
		{
			name: "valid rewrite with path_pattern",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "api.example.com", TargetIP: "10.0.0.1", PathPattern: "^/v1/"},
				}
			},
		},
		{
			name: "invalid rewrite path_pattern regex",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "api.example.com", TargetIP: "10.0.0.1", PathPattern: "[invalid"},
				}
			},
			wantErr: true,
			errMsg:  "invalid path_pattern",
		},
		{
			name: "valid rewrite with target_scheme http",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "example.com", TargetIP: "10.0.0.1", TargetScheme: "http"},
				}
			},
		},
		{
			name: "valid rewrite with target_scheme https",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "example.com", TargetIP: "10.0.0.1", TargetScheme: "https"},
				}
			},
		},
		{
			name: "invalid rewrite target_scheme",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "example.com", TargetIP: "10.0.0.1", TargetScheme: "ftp"},
				}
			},
			wantErr: true,
			errMsg:  "invalid target_scheme",
		},
		{
			name: "valid rewrite with drop_headers",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "example.com", TargetIP: "10.0.0.1", DropHeaders: []string{"Authorization", "Cookie"}},
				}
			},
		},
		{
			name: "duplicate exact domain without path_pattern",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "api.example.com", TargetIP: "10.0.0.1"},
					{Domain: "api.example.com", TargetIP: "10.0.0.2"},
				}
			},
			wantErr: true,
			errMsg:  "duplicate domain",
		},
		{
			name: "same domain with different path_patterns is valid",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "api.example.com", TargetIP: "10.0.0.1", PathPattern: "^/v1/"},
					{Domain: "api.example.com", TargetIP: "10.0.0.2", PathPattern: "^/v2/"},
				}
			},
		},
		{
			name: "same domain with path_pattern and catch-all is valid",
			modify: func(c *Config) {
				c.Proxy.MitmCertPath = "/path/to/cert"
				c.Proxy.MitmKeyPath = "/path/to/key"
				c.Rewrites = []RewriteRule{
					{Domain: "api.example.com", TargetIP: "10.0.0.1", PathPattern: "^/v1/"},
					{Domain: "api.example.com", TargetIP: "10.0.0.2"},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			tt.modify(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil {
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

func TestConfigApplyEnvOverrides(t *testing.T) {
	t.Setenv("PROXY_PORT", "9999")
	t.Setenv("PROXY_DEFAULT_POLICY", "ALLOW")
	t.Setenv("PROXY_MITM_KEYSTORE_PATH", "/path/to/keystore.p12")
	t.Setenv("PROXY_MITM_KEYSTORE_PASSWORD", "secret")
	t.Setenv("PROXY_BLOCKED_LOG_PATH", "/var/log/blocked.json")
	t.Setenv("PROXY_OUTGOING_TRUSTSTORE_PATH", "/path/to/truststore.p12")
	t.Setenv("PROXY_OUTGOING_TRUSTSTORE_PASSWORD", "truststorepass")
	t.Setenv("PROXY_INSECURE_SKIP_VERIFY", "true")

	cfg := Config{}
	cfg.ApplyEnvOverrides()

	if cfg.Proxy.Port != "9999" {
		t.Errorf("ApplyEnvOverrides() Port = %v, want %v", cfg.Proxy.Port, "9999")
	}
	if cfg.Proxy.DefaultPolicy != "ALLOW" {
		t.Errorf("ApplyEnvOverrides() DefaultPolicy = %v, want %v", cfg.Proxy.DefaultPolicy, "ALLOW")
	}
	if cfg.Proxy.MitmKeystorePath != "/path/to/keystore.p12" {
		t.Errorf("ApplyEnvOverrides() MitmKeystorePath = %v, want %v", cfg.Proxy.MitmKeystorePath, "/path/to/keystore.p12")
	}
	if cfg.Proxy.MitmKeystorePassword != "secret" {
		t.Errorf("ApplyEnvOverrides() MitmKeystorePassword = %v, want %v", cfg.Proxy.MitmKeystorePassword, "secret")
	}
	if cfg.Proxy.BlockedLogPath != "/var/log/blocked.json" {
		t.Errorf("ApplyEnvOverrides() BlockedLogPath = %v, want %v", cfg.Proxy.BlockedLogPath, "/var/log/blocked.json")
	}
	if cfg.Proxy.OutgoingTruststorePath != "/path/to/truststore.p12" {
		t.Errorf("ApplyEnvOverrides() OutgoingTruststorePath = %v, want %v", cfg.Proxy.OutgoingTruststorePath, "/path/to/truststore.p12")
	}
	if cfg.Proxy.OutgoingTruststorePassword != "truststorepass" {
		t.Errorf("ApplyEnvOverrides() OutgoingTruststorePassword = %v, want %v", cfg.Proxy.OutgoingTruststorePassword, "truststorepass")
	}
	if !cfg.Proxy.InsecureSkipVerify {
		t.Error("ApplyEnvOverrides() InsecureSkipVerify = false, want true")
	}
}

func TestConfigApplyEnvOverridesInsecureNotSet(t *testing.T) {
	cfg := Config{}
	cfg.ApplyEnvOverrides()

	if cfg.Proxy.InsecureSkipVerify {
		t.Error("ApplyEnvOverrides() InsecureSkipVerify = true without env var, want false")
	}
}

func TestWildcardToRegex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		matches []string
		noMatch []string
		wantErr bool
	}{
		{
			name:    "exact match",
			pattern: "example.com",
			matches: []string{"example.com"},
			noMatch: []string{"sub.example.com", "example.org", "notexample.com"},
		},
		{
			name:    "wildcard subdomain",
			pattern: "*.example.com",
			matches: []string{"sub.example.com", "api.example.com", "test.example.com", "sub.sub.example.com", "a.b.c.example.com"},
			noMatch: []string{"example.com", "example.org"},
		},
		{
			name:    "full wildcard",
			pattern: "*",
			matches: []string{"anything.com", "example.org", "test"},
		},
		{
			name:    "domain with special chars",
			pattern: "api-v2.example.com",
			matches: []string{"api-v2.example.com"},
			noMatch: []string{"api.v2.example.com", "apiv2.example.com"},
		},
		{
			name:    "regex with tilde prefix anchored",
			pattern: `~^api[0-9]+\.example\.com$`,
			matches: []string{"api1.example.com", "api42.example.com"},
			noMatch: []string{"api.example.com", "xapi1.example.com"},
		},
		{
			name:    "regex with tilde prefix unanchored",
			pattern: `~\.internal\.`,
			matches: []string{"foo.internal.bar", "a.internal.b.c"},
			noMatch: []string{"internal", "foointernal"},
		},
		{
			name:    "regex with tilde prefix invalid",
			pattern: `~[`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, err := WildcardToRegex(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("WildcardToRegex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			for _, m := range tt.matches {
				if !re.MatchString(m) {
					t.Errorf("WildcardToRegex(%q) should match %q", tt.pattern, m)
				}
			}
			for _, m := range tt.noMatch {
				if re.MatchString(m) {
					t.Errorf("WildcardToRegex(%q) should not match %q", tt.pattern, m)
				}
			}
		})
	}
}

func TestCompileACL(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid patterns",
			config: Config{
				ACL: struct {
					Whitelist   []string `yaml:"whitelist"`
					Blacklist   []string `yaml:"blacklist"`
					Passthrough []string `yaml:"passthrough"`
				}{
					Whitelist: []string{`*.google.com`, `github.com`},
					Blacklist: []string{`*.tiktok.com`},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid whitelist pattern",
			config: Config{
				ACL: struct {
					Whitelist   []string `yaml:"whitelist"`
					Blacklist   []string `yaml:"blacklist"`
					Passthrough []string `yaml:"passthrough"`
				}{
					Whitelist: []string{`~[invalid`},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid blacklist pattern",
			config: Config{
				ACL: struct {
					Whitelist   []string `yaml:"whitelist"`
					Blacklist   []string `yaml:"blacklist"`
					Passthrough []string `yaml:"passthrough"`
				}{
					Blacklist: []string{`~[invalid`},
				},
			},
			wantErr: true,
		},
		{
			name: "valid passthrough patterns",
			config: Config{
				ACL: struct {
					Whitelist   []string `yaml:"whitelist"`
					Blacklist   []string `yaml:"blacklist"`
					Passthrough []string `yaml:"passthrough"`
				}{
					Passthrough: []string{`kubernetes.default.svc`, `*.internal.local`},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid passthrough pattern",
			config: Config{
				ACL: struct {
					Whitelist   []string `yaml:"whitelist"`
					Blacklist   []string `yaml:"blacklist"`
					Passthrough []string `yaml:"passthrough"`
				}{
					Passthrough: []string{`~[invalid`},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompileACL(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompileACL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	p1, _ := WildcardToRegex("*.google.com")
	p2, _ := WildcardToRegex("github.com")
	patterns := []*regexp.Regexp{p1, p2}

	tests := []struct {
		host string
		want bool
	}{
		{"www.google.com", true},
		{"api.google.com", true},
		{"github.com", true},
		{"google.com", false},
		{"notgoogle.com", false},
		{"github.org", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := Matches(tt.host, patterns); got != tt.want {
				t.Errorf("Matches(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestMatchesPassthrough(t *testing.T) {
	p1, _ := WildcardToRegex("kubernetes.default.svc")
	p2, _ := WildcardToRegex("*.internal.local")
	patterns := []*regexp.Regexp{p1, p2}

	tests := []struct {
		host string
		want bool
	}{
		{"kubernetes.default.svc", true},
		{"api.internal.local", true},
		{"deep.sub.internal.local", true},
		{"internal.local", false},
		{"kubernetes.default", false},
		{"other.svc", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := Matches(tt.host, patterns); got != tt.want {
				t.Errorf("Matches(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestCompileRewrites(t *testing.T) {
	tests := []struct {
		name    string
		rules   []RewriteRule
		wantLen int
		wantErr bool
	}{
		{
			name: "exact and wildcard rules",
			rules: []RewriteRule{
				{Domain: "api.example.com", TargetIP: "10.0.0.1"},
				{Domain: "*.internal.com", TargetIP: "10.0.0.2"},
			},
			wantLen: 2,
			wantErr: false,
		},
		{
			name: "rules with target_host",
			rules: []RewriteRule{
				{Domain: "api.example.com", TargetHost: "internal.example.com"},
				{Domain: "*.internal.com", TargetIP: "10.0.0.2"},
			},
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "empty rules",
			rules:   []RewriteRule{},
			wantLen: 0,
			wantErr: false,
		},
		{
			name: "rules with path_pattern",
			rules: []RewriteRule{
				{Domain: "api.example.com", TargetIP: "10.0.0.1", PathPattern: "^/v1/"},
				{Domain: "api.example.com", TargetIP: "10.0.0.2", PathPattern: "^/v2/"},
				{Domain: "api.example.com", TargetIP: "10.0.0.3"},
			},
			wantLen: 3,
			wantErr: false,
		},
		{
			name: "invalid path_pattern",
			rules: []RewriteRule{
				{Domain: "api.example.com", TargetIP: "10.0.0.1", PathPattern: "[invalid"},
			},
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompileRewrites(tt.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompileRewrites() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("CompileRewrites() returned %d rules, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestCompileRewritesPathPattern(t *testing.T) {
	rules := []RewriteRule{
		{Domain: "api.example.com", TargetIP: "10.0.0.1", PathPattern: "^/v1/"},
		{Domain: "api.example.com", TargetIP: "10.0.0.2"},
	}
	compiled, err := CompileRewrites(rules)
	if err != nil {
		t.Fatalf("CompileRewrites() error = %v", err)
	}
	if compiled[0].PathPattern == nil {
		t.Error("compiled[0].PathPattern should be non-nil for rule with path_pattern")
	}
	if !compiled[0].PathPattern.MatchString("/v1/users") {
		t.Error("compiled[0].PathPattern should match /v1/users")
	}
	if compiled[0].PathPattern.MatchString("/v2/users") {
		t.Error("compiled[0].PathPattern should not match /v2/users")
	}
	if compiled[1].PathPattern != nil {
		t.Error("compiled[1].PathPattern should be nil for rule without path_pattern")
	}
}

func TestRuntimeConfigUpdateAndGet(t *testing.T) {
	rc := &RuntimeConfig{}

	cfg := Config{}
	cfg.Proxy.Port = "8080"
	cfg.Proxy.DefaultPolicy = "BLOCK"

	acl := CompiledACL{
		Whitelist: []*regexp.Regexp{regexp.MustCompile(`google\.com`)},
	}

	rewrites := []CompiledRewriteRule{
		{
			Pattern:  regexp.MustCompile(`^api\.example\.com$`),
			TargetIP: "10.0.0.1",
			Original: "api.example.com",
		},
	}

	_ = rc.Update(cfg, acl, rewrites, nil, nil, nil)

	gotCfg, gotACL, gotRewrites, gotExact, _ := rc.Get()

	if gotCfg.Proxy.Port != "8080" {
		t.Errorf("Get() config.Port = %v, want %v", gotCfg.Proxy.Port, "8080")
	}
	if len(gotACL.Whitelist) != 1 {
		t.Errorf("Get() ACL.Whitelist length = %v, want %v", len(gotACL.Whitelist), 1)
	}
	if len(gotRewrites) != 1 {
		t.Errorf("Get() rewrites length = %v, want %v", len(gotRewrites), 1)
	}
	if _, ok := gotExact["api.example.com"]; !ok {
		t.Error("Get() exactMap should contain api.example.com")
	}
}

func TestOpenBlockedLog(t *testing.T) {
	t.Run("empty path returns nil", func(t *testing.T) {
		logger, f, err := OpenBlockedLog("")
		if err != nil {
			t.Fatalf("OpenBlockedLog(\"\") error = %v", err)
		}
		if logger != nil {
			t.Error("expected nil logger for empty path")
		}
		if f != nil {
			t.Error("expected nil file for empty path")
		}
	})

	t.Run("valid path creates file with 0600", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blocked.log")
		logger, f, err := OpenBlockedLog(path)
		if err != nil {
			t.Fatalf("OpenBlockedLog() error = %v", err)
		}
		t.Cleanup(func() { f.Close() }) //nolint:errcheck // test cleanup

		if logger == nil {
			t.Fatal("expected non-nil logger")
		}
		if f == nil {
			t.Fatal("expected non-nil file")
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat blocked log: %v", err)
		}
		if runtime.GOOS != "windows" {
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("file permissions = %o, want 0600", perm)
			}
		}
	})

	t.Run("invalid directory returns error", func(t *testing.T) {
		_, _, err := OpenBlockedLog(filepath.Join(t.TempDir(), "does-not-exist", "blocked.log"))
		if err == nil {
			t.Fatal("expected error for invalid directory")
		}
	})
}

func TestBlockedLoggerWritesJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.log")
	logger, f, err := OpenBlockedLog(path)
	if err != nil {
		t.Fatalf("OpenBlockedLog() error = %v", err)
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "blocked",
		slog.String("request_id", "abc123"),
		slog.String("client", "127.0.0.1:9999"),
		slog.String("host", "evil.com"),
		slog.String("method", "GET"),
		slog.String("path", "/malware"),
		slog.String("action", "BLACK-LISTED"),
	)
	f.Close() //nolint:errcheck // flush before read

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read blocked log: %v", err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal JSON log entry: %v (raw: %s)", err, data)
	}

	wantKeys := []string{"request_id", "client", "host", "method", "path", "action", "msg", "level", "time"}
	for _, key := range wantKeys {
		if _, ok := entry[key]; !ok {
			t.Errorf("missing key %q in JSON log entry", key)
		}
	}
	if entry["request_id"] != "abc123" {
		t.Errorf("request_id = %v, want %q", entry["request_id"], "abc123")
	}
	if entry["action"] != "BLACK-LISTED" {
		t.Errorf("action = %v, want %q", entry["action"], "BLACK-LISTED")
	}
	if entry["msg"] != "blocked" {
		t.Errorf("msg = %v, want %q", entry["msg"], "blocked")
	}
}

func TestRuntimeConfigBlockedLogger(t *testing.T) {
	t.Run("nil when disabled", func(t *testing.T) {
		rc := &RuntimeConfig{}
		_ = rc.Update(Config{}, CompiledACL{}, nil, nil, nil, nil)

		if got := rc.GetBlockedLogger(); got != nil {
			t.Error("GetBlockedLogger() should return nil when disabled")
		}
	})

	t.Run("returns logger when enabled", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blocked.log")
		logger, f, err := OpenBlockedLog(path)
		if err != nil {
			t.Fatalf("OpenBlockedLog() error = %v", err)
		}

		rc := &RuntimeConfig{}
		_ = rc.Update(Config{}, CompiledACL{}, nil, nil, logger, f)

		if got := rc.GetBlockedLogger(); got == nil {
			t.Error("GetBlockedLogger() should return non-nil logger when enabled")
		}

		rc.CloseBlockedLog()

		if got := rc.GetBlockedLogger(); got != nil {
			t.Error("GetBlockedLogger() should return nil after CloseBlockedLog()")
		}
	})
}

func TestRunValidate(t *testing.T) {
	// Create temp dir with cert/key files for valid tests
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "ca.crt")
	keyFile := filepath.Join(tmpDir, "ca.key")
	if err := os.WriteFile(certFile, []byte("fake-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("fake-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	writeConfig := func(t *testing.T, content string) string {
		t.Helper()
		f := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}

	t.Run("valid config with existing cert files", func(t *testing.T) {
		cfg := writeConfig(t, `
proxy:
  mitm_cert_path: "`+certFile+`"
  mitm_key_path: "`+keyFile+`"
  default_policy: BLOCK
acl:
  whitelist:
    - "*.google.com"
rewrites:
  - domain: "api.example.com"
    target_ip: "10.0.0.1"
`)
		if err := RunValidate(cfg); err != nil {
			t.Errorf("RunValidate() unexpected error: %v", err)
		}
	})

	t.Run("valid config with missing cert file", func(t *testing.T) {
		cfg := writeConfig(t, `
proxy:
  mitm_cert_path: "/nonexistent/ca.crt"
  mitm_key_path: "`+keyFile+`"
  default_policy: BLOCK
`)
		err := RunValidate(cfg)
		if err == nil {
			t.Fatal("RunValidate() expected error for missing cert file, got nil")
		}
		if !contains(err.Error(), "mitm_cert_path") {
			t.Errorf("RunValidate() error = %v, want error mentioning mitm_cert_path", err)
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		cfg := writeConfig(t, `{{{invalid yaml`)
		err := RunValidate(cfg)
		if err == nil {
			t.Fatal("RunValidate() expected error for invalid YAML, got nil")
		}
	})

	t.Run("invalid ACL pattern", func(t *testing.T) {
		cfg := writeConfig(t, `
proxy:
  mitm_cert_path: "`+certFile+`"
  mitm_key_path: "`+keyFile+`"
acl:
  whitelist:
    - "~[invalid"
`)
		err := RunValidate(cfg)
		if err == nil {
			t.Fatal("RunValidate() expected error for invalid pattern, got nil")
		}
	})

	t.Run("nonexistent config file", func(t *testing.T) {
		err := RunValidate("/nonexistent/config.yaml")
		if err == nil {
			t.Fatal("RunValidate() expected error for nonexistent config, got nil")
		}
	})
}

func TestCompileRewritesTargetSchemeAndDropHeaders(t *testing.T) {
	rules := []RewriteRule{
		{Domain: "legacy.example.com", TargetIP: "10.0.0.1", TargetScheme: "http", DropHeaders: []string{"Authorization", "Cookie"}},
		{Domain: "plain.example.com", TargetIP: "10.0.0.2"},
	}

	compiled, err := CompileRewrites(rules)
	if err != nil {
		t.Fatalf("CompileRewrites() error = %v", err)
	}

	if len(compiled) != 2 {
		t.Fatalf("CompileRewrites() returned %d rules, want 2", len(compiled))
	}
	if compiled[0].TargetScheme != "http" {
		t.Errorf("compiled[0].TargetScheme = %q, want %q", compiled[0].TargetScheme, "http")
	}
	if len(compiled[0].DropHeaders) != 2 {
		t.Errorf("compiled[0].DropHeaders length = %d, want 2", len(compiled[0].DropHeaders))
	}
	if compiled[0].DropHeaders[0] != "Authorization" {
		t.Errorf("compiled[0].DropHeaders[0] = %q, want %q", compiled[0].DropHeaders[0], "Authorization")
	}
	if compiled[0].DropHeaders[1] != "Cookie" {
		t.Errorf("compiled[0].DropHeaders[1] = %q, want %q", compiled[0].DropHeaders[1], "Cookie")
	}
	if compiled[1].TargetScheme != "" {
		t.Errorf("compiled[1].TargetScheme = %q, want empty", compiled[1].TargetScheme)
	}
	if len(compiled[1].DropHeaders) != 0 {
		t.Errorf("compiled[1].DropHeaders length = %d, want 0", len(compiled[1].DropHeaders))
	}
}

func TestCompileRewritesInsecure(t *testing.T) {
	rules := []RewriteRule{
		{Domain: "secure.example.com", TargetIP: "10.0.0.1", Insecure: false},
		{Domain: "insecure.internal.com", TargetIP: "10.0.0.2", Insecure: true},
		{Domain: "*.wild.internal.com", TargetIP: "10.0.0.3", Insecure: true},
	}

	compiled, err := CompileRewrites(rules)
	if err != nil {
		t.Fatalf("CompileRewrites() error = %v", err)
	}

	if len(compiled) != 3 {
		t.Fatalf("CompileRewrites() returned %d rules, want 3", len(compiled))
	}
	if compiled[0].Insecure {
		t.Error("compiled[0].Insecure = true, want false")
	}
	if !compiled[1].Insecure {
		t.Error("compiled[1].Insecure = false, want true")
	}
	if !compiled[2].Insecure {
		t.Error("compiled[2].Insecure = false, want true")
	}
}

func TestRuntimeConfigUpdateExcludesPathDomains(t *testing.T) {
	rc := &RuntimeConfig{}
	rewrites := []CompiledRewriteRule{
		{
			Pattern:     regexp.MustCompile(`^api\.example\.com$`),
			PathPattern: regexp.MustCompile(`^/v1/`),
			TargetIP:    "10.0.0.1",
			Original:    "api.example.com",
		},
		{
			Pattern:  regexp.MustCompile(`^api\.example\.com$`),
			TargetIP: "10.0.0.3",
			Original: "api.example.com",
		},
		{
			Pattern:  regexp.MustCompile(`^simple\.example\.com$`),
			TargetIP: "10.0.0.5",
			Original: "simple.example.com",
		},
	}

	_ = rc.Update(Config{}, CompiledACL{}, rewrites, nil, nil, nil)
	_, _, _, exactMap, _ := rc.Get()

	// api.example.com has at least one path-pattern rule -> excluded from exact map
	if _, ok := exactMap["api.example.com"]; ok {
		t.Error("api.example.com should be excluded from exact map (has path-pattern rules)")
	}

	// simple.example.com has no path rules -> should be in exact map
	if _, ok := exactMap["simple.example.com"]; !ok {
		t.Error("simple.example.com should be in exact map (no path-pattern rules)")
	}
}

func TestRuntimeConfigUpdateExactMapFirstMatchWins(t *testing.T) {
	rc := &RuntimeConfig{}

	// Simulate two rules for the same exact domain (no path patterns).
	// In practice Validate() rejects this, but Update() should still be
	// defensive and keep the first rule (YAML order / first-match-wins).
	rewrites := []CompiledRewriteRule{
		{
			Pattern:  regexp.MustCompile(`^dup\.example\.com$`),
			TargetIP: "10.0.0.1",
			Original: "dup.example.com",
			Headers:  map[string]string{"X-First": "true"},
		},
		{
			Pattern:  regexp.MustCompile(`^dup\.example\.com$`),
			TargetIP: "10.0.0.2",
			Original: "dup.example.com",
			Headers:  map[string]string{"X-Second": "true"},
		},
	}

	_ = rc.Update(Config{}, CompiledACL{}, rewrites, nil, nil, nil)
	_, _, _, exactMap, _ := rc.Get()

	rw, ok := exactMap["dup.example.com"]
	if !ok {
		t.Fatal("dup.example.com should be in exact map")
	}
	if rw.TargetIP != "10.0.0.1" {
		t.Errorf("exactMap[dup.example.com].TargetIP = %q, want %q (first rule should win)", rw.TargetIP, "10.0.0.1")
	}
	if _, hasFirst := rw.Headers["X-First"]; !hasFirst {
		t.Error("exactMap should contain the first rule's headers")
	}
}

func TestRunValidateTruststore(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "ca.crt")
	keyFile := filepath.Join(tmpDir, "ca.key")
	truststoreFile := filepath.Join(tmpDir, "truststore.p12")
	if err := os.WriteFile(certFile, []byte("fake-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("fake-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(truststoreFile, []byte("fake-truststore"), 0o600); err != nil {
		t.Fatal(err)
	}

	writeConfig := func(t *testing.T, content string) string {
		t.Helper()
		f := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}

	t.Run("valid config with existing truststore file", func(t *testing.T) {
		cfg := writeConfig(t, `
proxy:
  mitm_cert_path: "`+certFile+`"
  mitm_key_path: "`+keyFile+`"
  outgoing_truststore_path: "`+truststoreFile+`"
  outgoing_truststore_password: "changeit"
  default_policy: BLOCK
`)
		if err := RunValidate(cfg); err != nil {
			t.Errorf("RunValidate() unexpected error: %v", err)
		}
	})

	t.Run("missing truststore file fails validation", func(t *testing.T) {
		cfg := writeConfig(t, `
proxy:
  mitm_cert_path: "`+certFile+`"
  mitm_key_path: "`+keyFile+`"
  outgoing_truststore_path: "/nonexistent/truststore.p12"
  outgoing_truststore_password: "changeit"
  default_policy: BLOCK
`)
		err := RunValidate(cfg)
		if err == nil {
			t.Fatal("RunValidate() expected error for missing truststore file, got nil")
		}
		if !contains(err.Error(), "outgoing_truststore_path") {
			t.Errorf("RunValidate() error = %v, want error mentioning outgoing_truststore_path", err)
		}
	})
}

func TestRunValidateOutgoingCA(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "ca.crt")
	keyFile := filepath.Join(tmpDir, "ca.key")
	caFile := filepath.Join(tmpDir, "extra-ca.crt")
	for _, f := range []string{certFile, keyFile, caFile} {
		if err := os.WriteFile(f, []byte("fake"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeConfig := func(t *testing.T, content string) string {
		t.Helper()
		f := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}

	t.Run("valid outgoing_ca files pass validation", func(t *testing.T) {
		cfg := writeConfig(t, `
proxy:
  mitm_cert_path: "`+certFile+`"
  mitm_key_path: "`+keyFile+`"
  default_policy: BLOCK
  outgoing_ca:
    - "`+caFile+`"
`)
		if err := RunValidate(cfg); err != nil {
			t.Errorf("RunValidate() unexpected error: %v", err)
		}
	})

	t.Run("missing outgoing_ca file fails validation", func(t *testing.T) {
		cfg := writeConfig(t, `
proxy:
  mitm_cert_path: "`+certFile+`"
  mitm_key_path: "`+keyFile+`"
  default_policy: BLOCK
  outgoing_ca:
    - "`+caFile+`"
    - "/nonexistent/missing-ca.crt"
`)
		err := RunValidate(cfg)
		if err == nil {
			t.Fatal("RunValidate() expected error for missing outgoing_ca file, got nil")
		}
		if !contains(err.Error(), "outgoing_ca[1]") {
			t.Errorf("RunValidate() error = %v, want error mentioning outgoing_ca[1]", err)
		}
	})
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
