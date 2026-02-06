package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/http2"
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
			re, err := wildcardToRegex(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("wildcardToRegex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			for _, m := range tt.matches {
				if !re.MatchString(m) {
					t.Errorf("wildcardToRegex(%q) should match %q", tt.pattern, m)
				}
			}
			for _, m := range tt.noMatch {
				if re.MatchString(m) {
					t.Errorf("wildcardToRegex(%q) should not match %q", tt.pattern, m)
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
					Whitelist []string `yaml:"whitelist"`
					Blacklist []string `yaml:"blacklist"`
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
					Whitelist []string `yaml:"whitelist"`
					Blacklist []string `yaml:"blacklist"`
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
					Whitelist []string `yaml:"whitelist"`
					Blacklist []string `yaml:"blacklist"`
				}{
					Blacklist: []string{`~[invalid`},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileACL(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileACL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	p1, _ := wildcardToRegex("*.google.com")
	p2, _ := wildcardToRegex("github.com")
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
			if got := matches(tt.host, patterns); got != tt.want {
				t.Errorf("matches(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestExtractBaseDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"a.b.c.d.example.com", "example.com"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := extractBaseDomain(tt.host); got != tt.want {
				t.Errorf("extractBaseDomain(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomainForMetrics(t *testing.T) {
	rewriteExact := map[string]*CompiledRewriteRule{
		"api.example.com": {TargetIP: "10.0.0.1"},
	}
	acl := CompiledACL{
		Whitelist: []*regexp.Regexp{regexp.MustCompile(`^.*\.google\.com$`)},
		Blacklist: []*regexp.Regexp{regexp.MustCompile(`^.*\.blocked\.com$`)},
	}

	tests := []struct {
		host string
		want string
	}{
		{"api.example.com", "api.example.com"}, // exact rewrite match
		{"www.google.com", "google.com"},       // whitelist match -> base domain
		{"sub.blocked.com", "blocked.com"},     // blacklist match -> base domain
		{"random.unknown.com", "_other"},       // no match -> _other
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := normalizeDomainForMetrics(tt.host, rewriteExact, acl); got != tt.want {
				t.Errorf("normalizeDomainForMetrics(%q) = %v, want %v", tt.host, got, tt.want)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compileRewrites(tt.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileRewrites() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("compileRewrites() returned %d rules, want %d", len(got), tt.wantLen)
			}
		})
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

	rc.Update(cfg, acl, rewrites)

	gotCfg, gotACL, gotRewrites, gotExact := rc.Get()

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

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	if id1 == "" {
		t.Error("generateRequestID() returned empty string")
	}
	if id1 == id2 {
		t.Error("generateRequestID() should return unique IDs")
	}
	if len(id1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("generateRequestID() returned ID of length %d, want 16", len(id1))
	}
}

func TestOutboundHTTP2TransportConfiguration(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	if err := http2.ConfigureTransport(tr); err != nil {
		t.Fatalf("http2.ConfigureTransport() error = %v", err)
	}

	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig should not be nil after ConfigureTransport")
	}

	if !slices.Contains(tr.TLSClientConfig.NextProtos, "h2") {
		t.Errorf("TLSClientConfig.NextProtos = %v, want it to contain \"h2\"", tr.TLSClientConfig.NextProtos)
	}
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
		if err := runValidate(cfg); err != nil {
			t.Errorf("runValidate() unexpected error: %v", err)
		}
	})

	t.Run("valid config with missing cert file", func(t *testing.T) {
		cfg := writeConfig(t, `
proxy:
  mitm_cert_path: "/nonexistent/ca.crt"
  mitm_key_path: "`+keyFile+`"
  default_policy: BLOCK
`)
		err := runValidate(cfg)
		if err == nil {
			t.Fatal("runValidate() expected error for missing cert file, got nil")
		}
		if !contains(err.Error(), "mitm_cert_path") {
			t.Errorf("runValidate() error = %v, want error mentioning mitm_cert_path", err)
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		cfg := writeConfig(t, `{{{invalid yaml`)
		err := runValidate(cfg)
		if err == nil {
			t.Fatal("runValidate() expected error for invalid YAML, got nil")
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
		err := runValidate(cfg)
		if err == nil {
			t.Fatal("runValidate() expected error for invalid pattern, got nil")
		}
	})

	t.Run("nonexistent config file", func(t *testing.T) {
		err := runValidate("/nonexistent/config.yaml")
		if err == nil {
			t.Fatal("runValidate() expected error for nonexistent config, got nil")
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
