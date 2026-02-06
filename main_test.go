package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
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

	_ = rc.Update(cfg, acl, rewrites, nil, nil)

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

func TestOpenBlockedLog(t *testing.T) {
	t.Run("empty path returns nil", func(t *testing.T) {
		logger, f, err := openBlockedLog("")
		if err != nil {
			t.Fatalf("openBlockedLog(\"\") error = %v", err)
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
		logger, f, err := openBlockedLog(path)
		if err != nil {
			t.Fatalf("openBlockedLog() error = %v", err)
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
		_, _, err := openBlockedLog(filepath.Join(t.TempDir(), "does-not-exist", "blocked.log"))
		if err == nil {
			t.Fatal("expected error for invalid directory")
		}
	})
}

func TestBlockedLoggerWritesJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.log")
	logger, f, err := openBlockedLog(path)
	if err != nil {
		t.Fatalf("openBlockedLog() error = %v", err)
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
		_ = rc.Update(Config{}, CompiledACL{}, nil, nil, nil)

		if got := rc.GetBlockedLogger(); got != nil {
			t.Error("GetBlockedLogger() should return nil when disabled")
		}
	})

	t.Run("returns logger when enabled", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blocked.log")
		logger, f, err := openBlockedLog(path)
		if err != nil {
			t.Fatalf("openBlockedLog() error = %v", err)
		}

		rc := &RuntimeConfig{}
		_ = rc.Update(Config{}, CompiledACL{}, nil, logger, f)

		if got := rc.GetBlockedLogger(); got == nil {
			t.Error("GetBlockedLogger() should return non-nil logger when enabled")
		}

		rc.CloseBlockedLog()

		if got := rc.GetBlockedLogger(); got != nil {
			t.Error("GetBlockedLogger() should return nil after CloseBlockedLog()")
		}
	})
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
	baseTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	tr := &http.Transport{
		TLSClientConfig:   baseTLS,
		ForceAttemptHTTP2: true,
	}

	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig should not be nil")
	}
	if !slices.Contains(tr.TLSClientConfig.NextProtos, "h2") {
		t.Errorf("TLSClientConfig.NextProtos = %v, want it to contain \"h2\"", tr.TLSClientConfig.NextProtos)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be true")
	}
}

// generateTestCert creates a self-signed CA certificate valid for the given duration.
func generateTestCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tlsCert
}

// captureLogs runs fn and returns the captured slog JSON output.
func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	old := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(old)
	fn()
	return buf.String()
}

func TestLogMITMCertInfo(t *testing.T) {
	// Save and restore global state
	origCa := goproxy.GoproxyCa
	defer func() { goproxy.GoproxyCa = origCa }()

	t.Run("valid long-lived cert", func(t *testing.T) {
		goproxy.GoproxyCa = generateTestCert(t,
			time.Now().Add(-24*time.Hour),
			time.Now().Add(365*24*time.Hour),
		)
		output := captureLogs(t, logMITMCertInfo)

		if !contains(output, "MITM CA certificate loaded") {
			t.Error("expected 'MITM CA certificate loaded' log line")
		}
		if !contains(output, "Test CA") {
			t.Error("expected subject/issuer to contain 'Test CA'")
		}
		if !contains(output, `"is_ca":true`) {
			t.Error("expected is_ca to be true")
		}
		if contains(output, "EXPIRED") || contains(output, "expires soon") {
			t.Error("should not warn about expiry for long-lived cert")
		}
	})

	t.Run("expired cert", func(t *testing.T) {
		goproxy.GoproxyCa = generateTestCert(t,
			time.Now().Add(-48*time.Hour),
			time.Now().Add(-1*time.Hour),
		)
		output := captureLogs(t, logMITMCertInfo)

		if !contains(output, "MITM CA certificate loaded") {
			t.Error("expected 'MITM CA certificate loaded' log line")
		}
		if !contains(output, "EXPIRED") {
			t.Error("expected expiry warning for expired cert")
		}
	})

	t.Run("expiring soon cert", func(t *testing.T) {
		goproxy.GoproxyCa = generateTestCert(t,
			time.Now().Add(-24*time.Hour),
			time.Now().Add(15*24*time.Hour), // 15 days left
		)
		output := captureLogs(t, logMITMCertInfo)

		if !contains(output, "MITM CA certificate loaded") {
			t.Error("expected 'MITM CA certificate loaded' log line")
		}
		if !contains(output, "expires soon") {
			t.Error("expected 'expires soon' warning for cert expiring in 15 days")
		}
	})

	t.Run("cert with pre-set Leaf", func(t *testing.T) {
		cert := generateTestCert(t,
			time.Now().Add(-24*time.Hour),
			time.Now().Add(365*24*time.Hour),
		)
		// Parse and set Leaf explicitly
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		cert.Leaf = leaf
		goproxy.GoproxyCa = cert

		output := captureLogs(t, logMITMCertInfo)

		if !contains(output, "MITM CA certificate loaded") {
			t.Error("expected 'MITM CA certificate loaded' log line")
		}
		if !contains(output, "Test CA") {
			t.Error("expected subject to contain 'Test CA'")
		}
	})

	t.Run("empty certificate", func(t *testing.T) {
		goproxy.GoproxyCa = tls.Certificate{}
		output := captureLogs(t, logMITMCertInfo)

		if output != "" {
			t.Errorf("expected no output for empty certificate, got: %s", output)
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

func TestLoadMITMFromPEM(t *testing.T) {
	// Save and restore the global goproxy CA to avoid test pollution.
	origCa := goproxy.GoproxyCa
	t.Cleanup(func() { goproxy.GoproxyCa = origCa })

	// Write a fresh CA cert+key to temp files.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	writeTestCAPEM(t, dir, "Custom Test CA", "Custom Test Org")

	t.Run("loads custom cert and replaces embedded default", func(t *testing.T) {
		// Reset to embedded default first.
		goproxy.GoproxyCa = origCa

		if err := loadMITMFromPEM(certPath, keyPath); err != nil {
			t.Fatalf("loadMITMFromPEM() error: %v", err)
		}

		// Parse the loaded certificate.
		if len(goproxy.GoproxyCa.Certificate) == 0 {
			t.Fatal("GoproxyCa has no certificate after loading")
		}
		leaf, err := x509.ParseCertificate(goproxy.GoproxyCa.Certificate[0])
		if err != nil {
			t.Fatalf("parse loaded certificate: %v", err)
		}

		// Verify it's our custom cert, not goproxy's embedded default.
		if leaf.Subject.CommonName != "Custom Test CA" {
			t.Errorf("loaded cert CN = %q, want %q", leaf.Subject.CommonName, "Custom Test CA")
		}
		if leaf.Issuer.Organization[0] != "Custom Test Org" {
			t.Errorf("loaded cert Org = %q, want %q", leaf.Issuer.Organization[0], "Custom Test Org")
		}
		if !leaf.IsCA {
			t.Error("loaded cert is not a CA")
		}

		// Confirm it's different from the embedded goproxy default.
		origLeaf, parseErr := x509.ParseCertificate(origCa.Certificate[0])
		if parseErr != nil {
			t.Fatalf("parse embedded cert: %v", parseErr)
		}
		if leaf.Subject.CommonName == origLeaf.Subject.CommonName {
			t.Error("loaded cert has the same CN as the embedded goproxy default — custom cert not loaded")
		}
	})

	t.Run("error on missing cert file", func(t *testing.T) {
		err := loadMITMFromPEM("/nonexistent/ca.crt", keyPath)
		if err == nil {
			t.Fatal("expected error for missing cert file")
		}
	})

	t.Run("error on missing key file", func(t *testing.T) {
		err := loadMITMFromPEM(certPath, "/nonexistent/ca.key")
		if err == nil {
			t.Fatal("expected error for missing key file")
		}
	})

	t.Run("error on invalid PEM content", func(t *testing.T) {
		badCert := filepath.Join(t.TempDir(), "bad.crt")
		if err := os.WriteFile(badCert, []byte("not-a-cert"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := loadMITMFromPEM(badCert, keyPath)
		if err == nil {
			t.Fatal("expected error for invalid PEM content")
		}
	})
}

// writeTestCAPEM generates a CA certificate and key as PEM files in dir.
func writeTestCAPEM(t *testing.T, dir, cn, org string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	err = os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0o600)
	if err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	err = os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600)
	if err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func TestCompileRewritesInsecure(t *testing.T) {
	rules := []RewriteRule{
		{Domain: "secure.example.com", TargetIP: "10.0.0.1", Insecure: false},
		{Domain: "insecure.internal.com", TargetIP: "10.0.0.2", Insecure: true},
		{Domain: "*.wild.internal.com", TargetIP: "10.0.0.3", Insecure: true},
	}

	compiled, err := compileRewrites(rules)
	if err != nil {
		t.Fatalf("compileRewrites() error = %v", err)
	}

	if len(compiled) != 3 {
		t.Fatalf("compileRewrites() returned %d rules, want 3", len(compiled))
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

func TestLookupRewrite(t *testing.T) {
	rewrites := []CompiledRewriteRule{
		{
			Pattern:  regexp.MustCompile(`^.+\.wild\.example\.com$`),
			TargetIP: "10.0.0.3",
			Original: "*.wild.example.com",
			Insecure: true,
		},
	}
	rewriteExact := map[string]*CompiledRewriteRule{
		"exact.example.com": {
			Pattern:  regexp.MustCompile(`^exact\.example\.com$`),
			TargetIP: "10.0.0.1",
			Original: "exact.example.com",
			Insecure: false,
		},
		"insecure.example.com": {
			Pattern:    regexp.MustCompile(`^insecure\.example\.com$`),
			TargetHost: "internal.corp.com",
			Original:   "insecure.example.com",
			Insecure:   true,
		},
	}

	tests := []struct {
		name      string
		host      string
		wantMatch bool
		wantIP    string
		wantHost  string
		wantInsec bool
	}{
		{
			name:      "exact match with target_ip",
			host:      "exact.example.com",
			wantMatch: true,
			wantIP:    "10.0.0.1",
		},
		{
			name:      "exact match with target_host and insecure",
			host:      "insecure.example.com",
			wantMatch: true,
			wantHost:  "internal.corp.com",
			wantInsec: true,
		},
		{
			name:      "wildcard pattern match",
			host:      "sub.wild.example.com",
			wantMatch: true,
			wantIP:    "10.0.0.3",
			wantInsec: true,
		},
		{
			name:      "no match",
			host:      "unknown.example.com",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := lookupRewrite(tt.host, rewrites, rewriteExact)
			if result.matched != tt.wantMatch {
				t.Errorf("lookupRewrite(%q).matched = %v, want %v", tt.host, result.matched, tt.wantMatch)
			}
			if result.targetIP != tt.wantIP {
				t.Errorf("lookupRewrite(%q).targetIP = %v, want %v", tt.host, result.targetIP, tt.wantIP)
			}
			if result.targetHost != tt.wantHost {
				t.Errorf("lookupRewrite(%q).targetHost = %v, want %v", tt.host, result.targetHost, tt.wantHost)
			}
			if result.insecure != tt.wantInsec {
				t.Errorf("lookupRewrite(%q).insecure = %v, want %v", tt.host, result.insecure, tt.wantInsec)
			}
		})
	}
}

func TestLoadTruststoreCerts(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	dir := t.TempDir()
	_, p12Path := generateTestP12(t, dir, "Test Truststore CA", "Test Org", "testpass")

	t.Run("loads certificates from valid truststore", func(t *testing.T) {
		certs, err := loadTruststoreCerts(p12Path, "testpass")
		if err != nil {
			t.Fatalf("loadTruststoreCerts() error = %v", err)
		}
		if len(certs) == 0 {
			t.Fatal("loadTruststoreCerts() returned no certificates")
		}
		if certs[0].Subject.CommonName != "Test Truststore CA" {
			t.Errorf("cert CN = %q, want %q", certs[0].Subject.CommonName, "Test Truststore CA")
		}
	})

	t.Run("error on wrong password", func(t *testing.T) {
		_, err := loadTruststoreCerts(p12Path, "wrongpass")
		if err == nil {
			t.Fatal("expected error for wrong password")
		}
	})

	t.Run("error on nonexistent file", func(t *testing.T) {
		_, err := loadTruststoreCerts("/nonexistent/truststore.p12", "testpass")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})

	t.Run("error on invalid data", func(t *testing.T) {
		badPath := filepath.Join(dir, "bad.p12")
		if err := os.WriteFile(badPath, []byte("not-a-p12"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadTruststoreCerts(badPath, "testpass")
		if err == nil {
			t.Fatal("expected error for invalid p12 data")
		}
	})
}

func TestLoadCertPoolWithTruststore(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	dir := t.TempDir()
	certPath, p12Path := generateTestP12(t, dir, "Pool Test CA", "Test Org", "pooltest")

	t.Run("pool with truststore only", func(t *testing.T) {
		pool := loadCertPool("", p12Path, "pooltest")
		if pool == nil {
			t.Fatal("loadCertPool() returned nil")
		}
	})

	t.Run("pool with PEM bundle and truststore", func(t *testing.T) {
		pool := loadCertPool(certPath, p12Path, "pooltest")
		if pool == nil {
			t.Fatal("loadCertPool() returned nil")
		}
	})

	t.Run("pool with no extra certs", func(t *testing.T) {
		pool := loadCertPool("", "", "")
		if pool == nil {
			t.Fatal("loadCertPool() returned nil")
		}
	})

	t.Run("pool with bad truststore path logs warning", func(t *testing.T) {
		output := captureLogs(t, func() {
			pool := loadCertPool("", "/nonexistent/truststore.p12", "pass")
			if pool == nil {
				t.Fatal("loadCertPool() returned nil")
			}
		})
		if !contains(output, "Failed to load truststore") {
			t.Errorf("expected warning about failed truststore load, got: %s", output)
		}
	})
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
		if err := runValidate(cfg); err != nil {
			t.Errorf("runValidate() unexpected error: %v", err)
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
		err := runValidate(cfg)
		if err == nil {
			t.Fatal("runValidate() expected error for missing truststore file, got nil")
		}
		if !contains(err.Error(), "outgoing_truststore_path") {
			t.Errorf("runValidate() error = %v, want error mentioning outgoing_truststore_path", err)
		}
	})
}

func TestOutboundHTTP2TransportWithDialTLSContext(t *testing.T) {
	baseTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	tr := &http.Transport{
		TLSClientConfig:   baseTLS,
		ForceAttemptHTTP2: true,
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, nil // stub for test
		},
	}

	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig should not be nil")
	}
	if !slices.Contains(tr.TLSClientConfig.NextProtos, "h2") {
		t.Errorf("TLSClientConfig.NextProtos = %v, want it to contain \"h2\"", tr.TLSClientConfig.NextProtos)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be true")
	}
	if tr.DialTLSContext == nil {
		t.Error("DialTLSContext should be set")
	}
}

// startTLSServer creates a TLS server with a self-signed certificate signed by a generated CA.
// Returns the listener address, CA cert pool (for trusted clients), and the CA cert (for building truststores).
func startTLSServer(t *testing.T) (addr string, caPool *x509.CertPool, caCertPEM []byte) {
	t.Helper()

	// Generate CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TLS Test CA", Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	caPool = x509.NewCertPool()
	caPool.AddCert(caCert)

	// Generate server cert signed by the CA
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "rewrite-insecure.test", "rewrite-trusted.test"},
	}
	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCertDER})
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})

	tlsCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("load server TLS keypair: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("start TLS listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	// Serve simple HTTP responses (listener is already TLS-wrapped, use Serve not ServeTLS)
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		srv.Serve(ln) //nolint:errcheck // background test server
	}()

	return ln.Addr().String(), caPool, caCertPEM
}

func TestMakeTLSDialer(t *testing.T) {
	srvAddr, caPool, _ := startTLSServer(t)
	srvHost, srvPort, err := net.SplitHostPort(srvAddr)
	if err != nil {
		t.Fatalf("split server addr: %v", err)
	}

	// Helper to create a RuntimeConfig with given settings
	setupRuntime := func(insecureGlobal bool, rewrites []CompiledRewriteRule) *RuntimeConfig {
		rc := &RuntimeConfig{}
		cfg := Config{}
		cfg.Proxy.InsecureSkipVerify = insecureGlobal
		_ = rc.Update(cfg, CompiledACL{}, rewrites, nil, nil)
		return rc
	}

	t.Run("per_rewrite_insecure_allows_self_signed", func(t *testing.T) {
		// Rewrite with insecure=true → TLS handshake succeeds even without CA in pool
		rewrites := []CompiledRewriteRule{
			{
				Pattern:  regexp.MustCompile(`^rewrite-insecure\.test$`),
				TargetIP: srvHost,
				Original: "rewrite-insecure.test",
				Insecure: true,
			},
		}
		rc := setupRuntime(false, rewrites)
		baseTLS := &tls.Config{MinVersion: tls.VersionTLS12} // empty RootCAs = system pool (won't trust test CA)

		dial := makeTLSDialer(rc, baseTLS)
		conn, err := dial(context.Background(), "tcp", net.JoinHostPort("rewrite-insecure.test", srvPort))
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		conn.Close() //nolint:errcheck // test cleanup
	})

	t.Run("trusted_ca_in_pool_allows_connection", func(t *testing.T) {
		// No insecure flag, but CA is in pool → handshake succeeds
		rewrites := []CompiledRewriteRule{
			{
				Pattern:  regexp.MustCompile(`^rewrite-trusted\.test$`),
				TargetIP: srvHost,
				Original: "rewrite-trusted.test",
				Insecure: false,
			},
		}
		rc := setupRuntime(false, rewrites)
		baseTLS := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    caPool,
		}

		dial := makeTLSDialer(rc, baseTLS)
		conn, err := dial(context.Background(), "tcp", net.JoinHostPort("rewrite-trusted.test", srvPort))
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		conn.Close() //nolint:errcheck // test cleanup
	})

	t.Run("rejects_untrusted_cert", func(t *testing.T) {
		// No insecure, no CA trust → handshake must fail
		rewrites := []CompiledRewriteRule{
			{
				Pattern:  regexp.MustCompile(`^rewrite-trusted\.test$`),
				TargetIP: srvHost,
				Original: "rewrite-trusted.test",
				Insecure: false,
			},
		}
		rc := setupRuntime(false, rewrites)
		baseTLS := &tls.Config{MinVersion: tls.VersionTLS12} // empty = system pool, won't trust test CA

		dial := makeTLSDialer(rc, baseTLS)
		_, err := dial(context.Background(), "tcp", net.JoinHostPort("rewrite-trusted.test", srvPort))
		if err == nil {
			t.Fatal("expected TLS handshake error for untrusted cert")
		}
	})

	t.Run("global_insecure_skip_verify", func(t *testing.T) {
		// Global insecure_skip_verify=true, no per-rewrite flag → succeeds
		rewrites := []CompiledRewriteRule{
			{
				Pattern:  regexp.MustCompile(`^rewrite-trusted\.test$`),
				TargetIP: srvHost,
				Original: "rewrite-trusted.test",
				Insecure: false,
			},
		}
		rc := setupRuntime(true, rewrites) // global insecure
		baseTLS := &tls.Config{MinVersion: tls.VersionTLS12}

		dial := makeTLSDialer(rc, baseTLS)
		conn, err := dial(context.Background(), "tcp", net.JoinHostPort("rewrite-trusted.test", srvPort))
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		conn.Close() //nolint:errcheck // test cleanup
	})
}

// generateTestP12 creates a self-signed CA certificate as PEM and PKCS#12 files using openssl.
// Returns the PEM cert path and the .p12 path.
func generateTestP12(t *testing.T, dir, cn, org, password string) (certPath, p12Path string) {
	t.Helper()
	keyPath := filepath.Join(dir, "ca.key")
	certPath = filepath.Join(dir, "ca.crt")
	p12Path = filepath.Join(dir, "truststore.p12")

	ctx := context.Background()

	//nolint:gosec // test helper: all arguments are test-controlled constants
	cmd := exec.CommandContext(ctx, "openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl genkey: %v\n%s", err, out)
	}

	//nolint:gosec // test helper: all arguments are test-controlled constants
	cmd = exec.CommandContext(ctx, "openssl", "req", "-new", "-x509", "-key", keyPath,
		"-out", certPath, "-days", "1", "-subj", "/CN="+cn+"/O="+org)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}

	//nolint:gosec // test helper: all arguments are test-controlled constants
	cmd = exec.CommandContext(ctx, "openssl", "pkcs12", "-export",
		"-in", certPath, "-inkey", keyPath,
		"-out", p12Path, "-passout", "pass:"+password,
		"-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "SHA1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl pkcs12: %v\n%s", err, out)
	}

	return certPath, p12Path
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
