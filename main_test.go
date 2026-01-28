package main

import (
	"os"
	"regexp"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with all fields",
			config: Config{
				Proxy: struct {
					Port             string `yaml:"port"`
					MetricsPort      string `yaml:"metrics_port"`
					DefaultPolicy    string `yaml:"default_policy"`
					OutgoingCABundle string `yaml:"outgoing_ca_bundle"`
					MitmCertPath     string `yaml:"mitm_cert_path"`
					MitmKeyPath      string `yaml:"mitm_key_path"`
				}{
					Port:          "8080",
					MetricsPort:   "9090",
					DefaultPolicy: "BLOCK",
					MitmCertPath:  "/path/to/cert",
					MitmKeyPath:   "/path/to/key",
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with defaults applied",
			config: Config{
				Proxy: struct {
					Port             string `yaml:"port"`
					MetricsPort      string `yaml:"metrics_port"`
					DefaultPolicy    string `yaml:"default_policy"`
					OutgoingCABundle string `yaml:"outgoing_ca_bundle"`
					MitmCertPath     string `yaml:"mitm_cert_path"`
					MitmKeyPath      string `yaml:"mitm_key_path"`
				}{
					MitmCertPath: "/path/to/cert",
					MitmKeyPath:  "/path/to/key",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid default policy",
			config: Config{
				Proxy: struct {
					Port             string `yaml:"port"`
					MetricsPort      string `yaml:"metrics_port"`
					DefaultPolicy    string `yaml:"default_policy"`
					OutgoingCABundle string `yaml:"outgoing_ca_bundle"`
					MitmCertPath     string `yaml:"mitm_cert_path"`
					MitmKeyPath      string `yaml:"mitm_key_path"`
				}{
					DefaultPolicy: "INVALID",
					MitmCertPath:  "/path/to/cert",
					MitmKeyPath:   "/path/to/key",
				},
			},
			wantErr: true,
			errMsg:  "invalid default_policy",
		},
		{
			name: "missing mitm cert path",
			config: Config{
				Proxy: struct {
					Port             string `yaml:"port"`
					MetricsPort      string `yaml:"metrics_port"`
					DefaultPolicy    string `yaml:"default_policy"`
					OutgoingCABundle string `yaml:"outgoing_ca_bundle"`
					MitmCertPath     string `yaml:"mitm_cert_path"`
					MitmKeyPath      string `yaml:"mitm_key_path"`
				}{
					MitmKeyPath: "/path/to/key",
				},
			},
			wantErr: true,
			errMsg:  "mitm_cert_path is required",
		},
		{
			name: "missing mitm key path",
			config: Config{
				Proxy: struct {
					Port             string `yaml:"port"`
					MetricsPort      string `yaml:"metrics_port"`
					DefaultPolicy    string `yaml:"default_policy"`
					OutgoingCABundle string `yaml:"outgoing_ca_bundle"`
					MitmCertPath     string `yaml:"mitm_cert_path"`
					MitmKeyPath      string `yaml:"mitm_key_path"`
				}{
					MitmCertPath: "/path/to/cert",
				},
			},
			wantErr: true,
			errMsg:  "mitm_key_path is required",
		},
		{
			name: "invalid rewrite target IP",
			config: Config{
				Proxy: struct {
					Port             string `yaml:"port"`
					MetricsPort      string `yaml:"metrics_port"`
					DefaultPolicy    string `yaml:"default_policy"`
					OutgoingCABundle string `yaml:"outgoing_ca_bundle"`
					MitmCertPath     string `yaml:"mitm_cert_path"`
					MitmKeyPath      string `yaml:"mitm_key_path"`
				}{
					MitmCertPath: "/path/to/cert",
					MitmKeyPath:  "/path/to/key",
				},
				Rewrites: []RewriteRule{
					{Domain: "example.com", TargetIP: "not-an-ip"},
				},
			},
			wantErr: true,
			errMsg:  "invalid target_ip",
		},
		{
			name: "valid rewrite rule",
			config: Config{
				Proxy: struct {
					Port             string `yaml:"port"`
					MetricsPort      string `yaml:"metrics_port"`
					DefaultPolicy    string `yaml:"default_policy"`
					OutgoingCABundle string `yaml:"outgoing_ca_bundle"`
					MitmCertPath     string `yaml:"mitm_cert_path"`
					MitmKeyPath      string `yaml:"mitm_key_path"`
				}{
					MitmCertPath: "/path/to/cert",
					MitmKeyPath:  "/path/to/key",
				},
				Rewrites: []RewriteRule{
					{Domain: "example.com", TargetIP: "10.0.0.1"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
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
	// Save and restore environment
	origPort := os.Getenv("PROXY_PORT")
	origPolicy := os.Getenv("PROXY_DEFAULT_POLICY")
	defer func() {
		os.Setenv("PROXY_PORT", origPort)
		os.Setenv("PROXY_DEFAULT_POLICY", origPolicy)
	}()

	os.Setenv("PROXY_PORT", "9999")
	os.Setenv("PROXY_DEFAULT_POLICY", "ALLOW")

	cfg := Config{}
	cfg.ApplyEnvOverrides()

	if cfg.Proxy.Port != "9999" {
		t.Errorf("ApplyEnvOverrides() Port = %v, want %v", cfg.Proxy.Port, "9999")
	}
	if cfg.Proxy.DefaultPolicy != "ALLOW" {
		t.Errorf("ApplyEnvOverrides() DefaultPolicy = %v, want %v", cfg.Proxy.DefaultPolicy, "ALLOW")
	}
}

func TestWildcardToRegex(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		matches  []string
		noMatch  []string
		wantErr  bool
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
			matches: []string{"sub.example.com", "api.example.com", "test.example.com"},
			noMatch: []string{"example.com", "sub.sub.example.com", "example.org"},
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
			name: "valid regex patterns",
			config: Config{
				ACL: struct {
					Whitelist []string `yaml:"whitelist"`
					Blacklist []string `yaml:"blacklist"`
				}{
					Whitelist: []string{`^.*\.google\.com$`, `github\.com`},
					Blacklist: []string{`^.*\.tiktok\.com$`},
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
					Whitelist: []string{`[invalid`},
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
					Blacklist: []string{`[invalid`},
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
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`^.*\.google\.com$`),
		regexp.MustCompile(`^github\.com$`),
	}

	tests := []struct {
		host  string
		want  bool
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
		{"api.example.com", "api.example.com"},           // exact rewrite match
		{"www.google.com", "google.com"},                  // whitelist match -> base domain
		{"sub.blocked.com", "blocked.com"},                // blacklist match -> base domain
		{"random.unknown.com", "_other"},                  // no match -> _other
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
