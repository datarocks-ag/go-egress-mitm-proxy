// Package config provides types, loading, validation, and compilation for proxy configuration.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"go-egress-proxy/internal/metrics"
)

// RewriteRule defines a domain rewrite configuration.
// When a request matches the Domain pattern, it will be routed to TargetIP or TargetHost
// and the specified Headers will be injected.
// Exactly one of TargetIP or TargetHost must be set.
type RewriteRule struct {
	Domain       string            `yaml:"domain"`        // Domain pattern (exact or wildcard like "*.example.com")
	PathPattern  string            `yaml:"path_pattern"`  // Optional regex matched against r.URL.Path
	TargetIP     string            `yaml:"target_ip"`     // IP address to route to (e.g., "10.0.0.1")
	TargetHost   string            `yaml:"target_host"`   // Hostname to route to (resolved via DNS at dial time)
	TargetScheme string            `yaml:"target_scheme"` // Optional: "http" or "https" to change request scheme
	Headers      map[string]string `yaml:"headers"`       // Headers to inject into the request
	DropHeaders  []string          `yaml:"drop_headers"`  // Headers to remove before forwarding
	Insecure     bool              `yaml:"insecure"`      // Skip TLS verification for this rewrite only
}

// CompiledRewriteRule holds a rewrite rule with its compiled pattern.
type CompiledRewriteRule struct {
	Pattern      *regexp.Regexp
	PathPattern  *regexp.Regexp // nil when no path_pattern is set
	TargetIP     string
	TargetHost   string
	TargetScheme string // "http" or "https" to change request scheme (empty = keep original)
	Headers      map[string]string
	DropHeaders  []string // Headers to remove before forwarding
	Original     string   // Original domain string for exact match optimization
	Insecure     bool     // Skip TLS verification for this rewrite only
}

// RewriteCtxKeyType is an unexported type for context keys to avoid collisions.
type RewriteCtxKeyType struct{}

// RewriteCtxKey is used to pass a matched rewrite result from handleRequest to the dialers.
var RewriteCtxKey = RewriteCtxKeyType{}

// Config holds the complete proxy configuration loaded from YAML.
type Config struct {
	Proxy struct {
		Port                       string   `yaml:"port"`                         // Proxy listen port (default: "8080")
		MetricsPort                string   `yaml:"metrics_port"`                 // Metrics/health endpoint port (default: "9090")
		DefaultPolicy              string   `yaml:"default_policy"`               // "ALLOW" or "BLOCK" for unmatched domains
		OutgoingCABundle           string   `yaml:"outgoing_ca_bundle"`           // Optional CA bundle for upstream TLS
		OutgoingCA                 []string `yaml:"outgoing_ca"`                  // Optional list of individual CA cert files
		OutgoingTruststorePath     string   `yaml:"outgoing_truststore_path"`     // Optional PKCS#12 truststore for upstream TLS
		OutgoingTruststorePassword string   `yaml:"outgoing_truststore_password"` // Password for outgoing truststore
		InsecureSkipVerify         bool     `yaml:"insecure_skip_verify"`         // Disable TLS verification globally
		MitmCertPath               string   `yaml:"mitm_cert_path"`               // Path to MITM CA certificate
		MitmKeyPath                string   `yaml:"mitm_key_path"`                // Path to MITM CA private key
		MitmKeystorePath           string   `yaml:"mitm_keystore_path"`           // Path to PKCS#12 keystore (.p12) containing cert and key
		MitmKeystorePassword       string   `yaml:"mitm_keystore_password"`       // Password for PKCS#12 keystore
		MitmOrg                    string   `yaml:"mitm_org"`                     // Custom Organization for MITM leaf certificates
		BlockedLogPath             string   `yaml:"blocked_log_path"`             // Optional path for blocked request log
	} `yaml:"proxy"`
	Rewrites []RewriteRule `yaml:"rewrites"` // Domain rewrite rules
	ACL      struct {
		Whitelist []string `yaml:"whitelist"` // Regex patterns to allow
		Blacklist []string `yaml:"blacklist"` // Regex patterns to block
	} `yaml:"acl"`
}

// CompiledACL holds pre-compiled regex patterns for efficient matching.
type CompiledACL struct {
	Whitelist []*regexp.Regexp
	Blacklist []*regexp.Regexp
}

// RuntimeConfig holds the compiled, thread-safe runtime configuration.
type RuntimeConfig struct {
	mu            sync.RWMutex
	config        Config
	acl           CompiledACL
	rewrites      []CompiledRewriteRule
	rewriteExact  map[string]*CompiledRewriteRule // Fast path for exact matches
	tlsConfig     *tls.Config                     // Outbound TLS config (rebuilt on reload)
	blockedLogger *slog.Logger                    // nil when blocked log feature disabled
	blockedFile   *os.File                        // underlying file handle for Close()
}

// Update atomically updates the runtime configuration.
// It returns the previous blocked log file (if any) so the caller can close it after releasing the lock.
func (rc *RuntimeConfig) Update(cfg Config, acl CompiledACL, rewrites []CompiledRewriteRule,
	tlsConfig *tls.Config, blockedLogger *slog.Logger, blockedFile *os.File) *os.File {
	// Collect domains that have at least one path-based rule.
	// These domains must be excluded from the exact map so that all their rules
	// are evaluated sequentially (preserving YAML order / first-match-wins).
	domainsWithPath := make(map[string]bool)
	for i := range rewrites {
		if rewrites[i].PathPattern != nil {
			domainsWithPath[rewrites[i].Original] = true
		}
	}

	exactMap := make(map[string]*CompiledRewriteRule)
	for i := range rewrites {
		if !strings.Contains(rewrites[i].Original, "*") && !domainsWithPath[rewrites[i].Original] {
			if _, exists := exactMap[rewrites[i].Original]; !exists {
				exactMap[rewrites[i].Original] = &rewrites[i]
			}
		}
	}

	rc.mu.Lock()
	oldFile := rc.blockedFile
	rc.config = cfg
	rc.acl = acl
	rc.rewrites = rewrites
	rc.rewriteExact = exactMap
	rc.tlsConfig = tlsConfig
	rc.blockedLogger = blockedLogger
	rc.blockedFile = blockedFile
	rc.mu.Unlock()

	return oldFile
}

// Get returns the current configuration (read-locked).
func (rc *RuntimeConfig) Get() (Config, CompiledACL, []CompiledRewriteRule, map[string]*CompiledRewriteRule, *tls.Config) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.config, rc.acl, rc.rewrites, rc.rewriteExact, rc.tlsConfig
}

// GetBlockedLogger returns the blocked request logger, or nil if disabled.
func (rc *RuntimeConfig) GetBlockedLogger() *slog.Logger {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.blockedLogger
}

// CloseBlockedLog closes the blocked log file handle, if open.
func (rc *RuntimeConfig) CloseBlockedLog() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.blockedFile != nil {
		if err := rc.blockedFile.Close(); err != nil {
			slog.Warn("Failed to close blocked log file", "err", err)
		}
		rc.blockedFile = nil
		rc.blockedLogger = nil
	}
}

// OpenBlockedLog opens (or creates) the blocked request log file and returns a JSON logger writing to it.
// If path is empty, the feature is disabled and nil values are returned.
func OpenBlockedLog(path string) (*slog.Logger, *os.File, error) {
	if path == "" {
		return nil, nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open blocked log: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(f, nil))
	return logger, f, nil
}

// Validate checks the configuration for required fields and valid values.
// It also applies defaults for optional fields.
func (c *Config) Validate() error {
	// Apply defaults
	if c.Proxy.Port == "" {
		c.Proxy.Port = "8080"
	}
	if c.Proxy.MetricsPort == "" {
		c.Proxy.MetricsPort = "9090"
	}
	if c.Proxy.DefaultPolicy == "" {
		c.Proxy.DefaultPolicy = "BLOCK"
	}

	// Validate required fields
	if c.Proxy.DefaultPolicy != "ALLOW" && c.Proxy.DefaultPolicy != "BLOCK" {
		return fmt.Errorf("invalid default_policy %q: must be ALLOW or BLOCK", c.Proxy.DefaultPolicy)
	}

	// Require either cert+key or keystore, but not both
	hasCertKey := c.Proxy.MitmCertPath != "" || c.Proxy.MitmKeyPath != ""
	hasKeystore := c.Proxy.MitmKeystorePath != ""
	if hasCertKey && hasKeystore {
		return errors.New("proxy.mitm_keystore_path and proxy.mitm_cert_path/mitm_key_path are mutually exclusive")
	}
	if !hasCertKey && !hasKeystore {
		return errors.New("proxy.mitm_cert_path and proxy.mitm_key_path are required (or use proxy.mitm_keystore_path)")
	}
	if hasCertKey {
		if c.Proxy.MitmCertPath == "" {
			return errors.New("proxy.mitm_cert_path is required")
		}
		if c.Proxy.MitmKeyPath == "" {
			return errors.New("proxy.mitm_key_path is required")
		}
	}
	if hasKeystore && c.Proxy.MitmKeystorePassword == "" {
		return errors.New("proxy.mitm_keystore_password is required when using proxy.mitm_keystore_path")
	}

	// Validate outgoing truststore
	if c.Proxy.OutgoingTruststorePath != "" && c.Proxy.OutgoingTruststorePassword == "" {
		return errors.New("proxy.outgoing_truststore_password is required when using proxy.outgoing_truststore_path")
	}

	// Validate rewrite rules
	for i, rw := range c.Rewrites {
		if rw.Domain == "" {
			return fmt.Errorf("rewrites[%d]: domain is required", i)
		}
		hasIP := rw.TargetIP != ""
		hasHost := rw.TargetHost != ""
		if hasIP && hasHost {
			return fmt.Errorf("rewrites[%d]: target_ip and target_host are mutually exclusive", i)
		}
		if !hasIP && !hasHost {
			return fmt.Errorf("rewrites[%d]: target_ip or target_host is required", i)
		}
		if hasIP && net.ParseIP(rw.TargetIP) == nil {
			return fmt.Errorf("rewrites[%d]: invalid target_ip %q", i, rw.TargetIP)
		}
		if rw.PathPattern != "" {
			if _, err := regexp.Compile(rw.PathPattern); err != nil {
				return fmt.Errorf("rewrites[%d]: invalid path_pattern %q: %w", i, rw.PathPattern, err)
			}
		}
		if rw.TargetScheme != "" && rw.TargetScheme != "http" && rw.TargetScheme != "https" {
			return fmt.Errorf("rewrites[%d]: invalid target_scheme %q: must be \"http\" or \"https\"", i, rw.TargetScheme)
		}
	}

	// Detect duplicate exact domains without path_pattern (second rule would be unreachable).
	// Domains with path_pattern are exempt because multiple path-based rules on the same
	// domain is the intended usage (first-match-wins).
	seen := make(map[string]int) // domain -> first index
	for i, rw := range c.Rewrites {
		if rw.PathPattern != "" {
			continue
		}
		if first, ok := seen[rw.Domain]; ok {
			return fmt.Errorf("rewrites[%d]: duplicate domain %q without path_pattern (first at rewrites[%d]); second rule is unreachable", i, rw.Domain, first)
		}
		seen[rw.Domain] = i
	}

	return nil
}

// ApplyEnvOverrides applies environment variable overrides to the configuration.
// Environment variables take precedence over YAML values.
func (c *Config) ApplyEnvOverrides() {
	if v := os.Getenv("PROXY_PORT"); v != "" {
		c.Proxy.Port = v
	}
	if v := os.Getenv("PROXY_METRICS_PORT"); v != "" {
		c.Proxy.MetricsPort = v
	}
	if v := os.Getenv("PROXY_DEFAULT_POLICY"); v != "" {
		c.Proxy.DefaultPolicy = v
	}
	if v := os.Getenv("PROXY_MITM_CERT_PATH"); v != "" {
		c.Proxy.MitmCertPath = v
	}
	if v := os.Getenv("PROXY_MITM_KEY_PATH"); v != "" {
		c.Proxy.MitmKeyPath = v
	}
	if v := os.Getenv("PROXY_OUTGOING_CA_BUNDLE"); v != "" {
		c.Proxy.OutgoingCABundle = v
	}
	if v := os.Getenv("PROXY_MITM_KEYSTORE_PATH"); v != "" {
		c.Proxy.MitmKeystorePath = v
	}
	if v := os.Getenv("PROXY_MITM_KEYSTORE_PASSWORD"); v != "" {
		c.Proxy.MitmKeystorePassword = v
	}
	if v := os.Getenv("PROXY_OUTGOING_TRUSTSTORE_PATH"); v != "" {
		c.Proxy.OutgoingTruststorePath = v
	}
	if v := os.Getenv("PROXY_OUTGOING_TRUSTSTORE_PASSWORD"); v != "" {
		c.Proxy.OutgoingTruststorePassword = v
	}
	if v := os.Getenv("PROXY_MITM_ORG"); v != "" {
		c.Proxy.MitmOrg = v
	}
	if v := os.Getenv("PROXY_INSECURE_SKIP_VERIFY"); v == "true" {
		c.Proxy.InsecureSkipVerify = true
	}
	if v := os.Getenv("PROXY_BLOCKED_LOG_PATH"); v != "" {
		c.Proxy.BlockedLogPath = v
	}
}

// RunValidate loads and validates the configuration without starting the proxy.
// It checks YAML parsing, pattern compilation, and file existence for referenced paths.
func RunValidate(configPath string) error {
	cfg, _, _, err := LoadAndCompileConfig(configPath)
	if err != nil {
		return err
	}

	// Check that all referenced files exist and are readable
	filesToCheck := map[string]string{
		"mitm_cert_path":           cfg.Proxy.MitmCertPath,
		"mitm_key_path":            cfg.Proxy.MitmKeyPath,
		"mitm_keystore_path":       cfg.Proxy.MitmKeystorePath,
		"outgoing_ca_bundle":       cfg.Proxy.OutgoingCABundle,
		"outgoing_truststore_path": cfg.Proxy.OutgoingTruststorePath,
	}
	for name, path := range filesToCheck {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("%s: close: %w", name, err)
		}
	}
	for i, path := range cfg.Proxy.OutgoingCA {
		if strings.TrimSpace(path) == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("outgoing_ca[%d]: %w", i, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("outgoing_ca[%d]: close: %w", i, err)
		}
	}

	// Validate blocked_log_path parent directory exists
	if cfg.Proxy.BlockedLogPath != "" {
		dir := filepath.Dir(cfg.Proxy.BlockedLogPath)
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("blocked_log_path: parent directory: %w", err)
		}
	}

	return nil
}

// LoadAndCompileConfig loads, validates, and compiles the configuration.
func LoadAndCompileConfig(path string) (Config, CompiledACL, []CompiledRewriteRule, error) {
	cfg, err := LoadConfig(path)
	if err != nil {
		return Config{}, CompiledACL{}, nil, err
	}

	acl, err := CompileACL(cfg)
	if err != nil {
		return Config{}, CompiledACL{}, nil, err
	}

	rewrites, err := CompileRewrites(cfg.Rewrites)
	if err != nil {
		return Config{}, CompiledACL{}, nil, err
	}

	return cfg, acl, rewrites, nil
}

// Matches checks if a host matches any of the compiled regex patterns.
func Matches(host string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(host) {
			return true
		}
	}
	return false
}

// CompileACL compiles all patterns in the configuration using WildcardToRegex.
// Patterns support exact match, wildcards (*.example.com), and raw regex (~<pattern>).
// Returns an error if any pattern is invalid.
func CompileACL(cfg Config) (CompiledACL, error) {
	c := CompiledACL{}
	for i, p := range cfg.ACL.Whitelist {
		re, err := WildcardToRegex(p)
		if err != nil {
			return CompiledACL{}, fmt.Errorf("invalid whitelist pattern[%d] %q: %w", i, p, err)
		}
		c.Whitelist = append(c.Whitelist, re)
	}
	for i, p := range cfg.ACL.Blacklist {
		re, err := WildcardToRegex(p)
		if err != nil {
			return CompiledACL{}, fmt.Errorf("invalid blacklist pattern[%d] %q: %w", i, p, err)
		}
		c.Blacklist = append(c.Blacklist, re)
	}
	return c, nil
}

// CompileRewrites compiles rewrite rules, converting wildcards to regex patterns.
func CompileRewrites(rules []RewriteRule) ([]CompiledRewriteRule, error) {
	compiled := make([]CompiledRewriteRule, 0, len(rules))
	for i, rule := range rules {
		pattern, err := WildcardToRegex(rule.Domain)
		if err != nil {
			return nil, fmt.Errorf("invalid rewrite domain[%d] %q: %w", i, rule.Domain, err)
		}
		var pathPattern *regexp.Regexp
		if rule.PathPattern != "" {
			pathPattern, err = regexp.Compile(rule.PathPattern)
			if err != nil {
				return nil, fmt.Errorf("invalid rewrite path_pattern[%d] %q: %w", i, rule.PathPattern, err)
			}
		}
		compiled = append(compiled, CompiledRewriteRule{
			Pattern:      pattern,
			PathPattern:  pathPattern,
			TargetIP:     rule.TargetIP,
			TargetHost:   rule.TargetHost,
			TargetScheme: rule.TargetScheme,
			Headers:      rule.Headers,
			DropHeaders:  rule.DropHeaders,
			Original:     rule.Domain,
			Insecure:     rule.Insecure,
		})
	}
	return compiled, nil
}

// WildcardToRegex converts a domain pattern with wildcards to a regex.
// Supports:
//   - Exact match: "example.com" -> "^example\.com$"
//   - Wildcard: "*.example.com" -> "^.+\.example\.com$" (matches any subdomain depth)
//   - Full wildcard: "*" -> ".*"
//   - Raw regex: "~<regex>" -> compiled as-is (no escaping/anchoring)
func WildcardToRegex(pattern string) (*regexp.Regexp, error) {
	if strings.HasPrefix(pattern, "~") {
		return regexp.Compile(pattern[1:])
	}

	if pattern == "*" {
		return regexp.Compile(".*")
	}

	// Escape regex special characters except *
	escaped := regexp.QuoteMeta(pattern)

	// Replace \* with appropriate regex
	// *.example.com -> matches any subdomain depth (e.g. a.b.c.example.com)
	if strings.HasPrefix(escaped, `\*\.`) {
		escaped = `.+\.` + escaped[4:]
	}

	// Anchor the pattern
	escaped = "^" + escaped + "$"

	return regexp.Compile(escaped)
}

// LoadConfig reads and validates the configuration file.
func LoadConfig(path string) (Config, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		metrics.ConfigLoadErrors.Inc()
		return Config{}, fmt.Errorf("read config file: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(f, &c); err != nil {
		metrics.ConfigLoadErrors.Inc()
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	// Apply environment variable overrides
	c.ApplyEnvOverrides()

	if err := c.Validate(); err != nil {
		metrics.ConfigLoadErrors.Inc()
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	return c, nil
}
