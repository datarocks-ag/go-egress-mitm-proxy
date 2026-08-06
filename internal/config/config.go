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

// rewriteCtxKeyType is an unexported type for context keys to avoid collisions.
type rewriteCtxKeyType struct{}

// RewriteCtxKey is used to pass a matched rewrite result from handleRequest to the dialers.
var RewriteCtxKey = rewriteCtxKeyType{}

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
		Whitelist   []string `yaml:"whitelist"`   // Regex patterns to allow
		Blacklist   []string `yaml:"blacklist"`   // Regex patterns to block
		Passthrough []string `yaml:"passthrough"` // Regex patterns to tunnel without MITM
	} `yaml:"acl"`
	Trace TraceConfig `yaml:"trace"` // Selective full-detail request tracing
}

// TraceConfig configures selective full-detail request tracing.
// When enabled, requests matching any rule are logged as a single aggregated
// JSON record covering the TCP/TLS, request, and response layers.
type TraceConfig struct {
	Enabled       bool        `yaml:"enabled"`        // Master switch; when false tracing is fully short-circuited
	LogPath       string      `yaml:"log_path"`       // Optional dedicated JSON-lines file; empty = main log stream
	RedactHeaders []string    `yaml:"redact_headers"` // Header names to mask, in addition to the built-in defaults
	RedactQuery   bool        `yaml:"redact_query"`   // Mask URL query-string values
	LogSecrets    bool        `yaml:"log_secrets"`    // Escape hatch: disable all redaction and log verbatim
	Rules         []TraceRule `yaml:"rules"`          // OR across rules; within a rule host AND url must both match
}

// TraceRule selects requests to trace by host and/or URL, with per-rule body capture.
// Host and URL use the same convention as ACL/rewrites (wildcard, or "~" prefix for raw regex).
type TraceRule struct {
	Host   string            `yaml:"host"`   // Matched against the request hostname (optional)
	URL    string            `yaml:"url"`    // Matched against the full request URL (optional)
	Bodies BodyCaptureConfig `yaml:"bodies"` // Per-rule request/response body capture
}

// BodyCaptureConfig controls request/response body capture for a trace rule.
type BodyCaptureConfig struct {
	Enabled          bool     `yaml:"enabled"`            // Capture bodies for this rule
	Capture          string   `yaml:"capture"`            // "request", "response", or "both" (default: both)
	MaxRequestBytes  int      `yaml:"max_request_bytes"`  // Per-request cap (default: 8192)
	MaxResponseBytes int      `yaml:"max_response_bytes"` // Per-response cap (default: 8192)
	ContentTypes     []string `yaml:"content_types"`      // Content types logged as text; others use on_binary
	OnBinary         string   `yaml:"on_binary"`          // "base64" or "skip" for non-text bodies (default: base64)
}

// CompiledTrace holds the compiled, ready-to-match trace configuration.
type CompiledTrace struct {
	Enabled       bool
	RedactHeaders map[string]bool // lowercased header names to mask (built-in defaults + user)
	RedactQuery   bool
	LogSecrets    bool
	Rules         []CompiledTraceRule
}

// CompiledTraceRule is a trace rule with its patterns compiled.
type CompiledTraceRule struct {
	Host   *regexp.Regexp // nil when no host pattern is set
	URL    *regexp.Regexp // nil when no url pattern is set
	Bodies CompiledBodyCapture
}

// CompiledBodyCapture is a body-capture config with defaults applied and directions resolved.
type CompiledBodyCapture struct {
	Enabled          bool
	CaptureRequest   bool
	CaptureResponse  bool
	MaxRequestBytes  int
	MaxResponseBytes int
	ContentTypes     []string // lowercased; supports "type/*" suffix wildcards
	OnBinary         string
}

// DefaultRedactHeaders are always masked unless log_secrets is set.
var DefaultRedactHeaders = []string{"authorization", "proxy-authorization", "cookie", "set-cookie"}

// DefaultBodyContentTypes are logged as text when no content_types are configured.
var DefaultBodyContentTypes = []string{"application/json", "text/*", "application/xml", "application/x-www-form-urlencoded"}

// Match returns the first trace rule matching the host (and full URL, when known), or nil.
// When hasURL is false (e.g. at CONNECT time, before the HTTP request is seen),
// rules carrying a URL pattern are skipped since the URL cannot yet be evaluated.
func (ct CompiledTrace) Match(host, fullURL string, hasURL bool) *CompiledTraceRule {
	if !ct.Enabled {
		return nil
	}
	for i := range ct.Rules {
		r := &ct.Rules[i]
		if r.Host != nil && !r.Host.MatchString(host) {
			continue
		}
		if r.URL != nil {
			if !hasURL || !r.URL.MatchString(fullURL) {
				continue
			}
		}
		return r
	}
	return nil
}

// CompileTrace validates and compiles the trace configuration.
func CompileTrace(tc TraceConfig) (CompiledTrace, error) {
	ct := CompiledTrace{
		Enabled:       tc.Enabled,
		RedactQuery:   tc.RedactQuery,
		LogSecrets:    tc.LogSecrets,
		RedactHeaders: make(map[string]bool),
	}
	for _, h := range DefaultRedactHeaders {
		ct.RedactHeaders[h] = true
	}
	for _, h := range tc.RedactHeaders {
		ct.RedactHeaders[strings.ToLower(strings.TrimSpace(h))] = true
	}

	for i, r := range tc.Rules {
		if r.Host == "" && r.URL == "" {
			return CompiledTrace{}, fmt.Errorf("trace.rules[%d]: must set host or url", i)
		}
		cr := CompiledTraceRule{}
		if r.Host != "" {
			re, err := WildcardToRegex(r.Host)
			if err != nil {
				return CompiledTrace{}, fmt.Errorf("invalid trace host[%d] %q: %w", i, r.Host, err)
			}
			cr.Host = re
		}
		if r.URL != "" {
			re, err := WildcardToURLRegex(r.URL)
			if err != nil {
				return CompiledTrace{}, fmt.Errorf("invalid trace url[%d] %q: %w", i, r.URL, err)
			}
			cr.URL = re
		}
		cb, err := compileBodyCapture(r.Bodies)
		if err != nil {
			return CompiledTrace{}, fmt.Errorf("trace.rules[%d].bodies: %w", i, err)
		}
		cr.Bodies = cb
		ct.Rules = append(ct.Rules, cr)
	}
	return ct, nil
}

func compileBodyCapture(b BodyCaptureConfig) (CompiledBodyCapture, error) {
	cb := CompiledBodyCapture{Enabled: b.Enabled}
	if !b.Enabled {
		return cb, nil
	}

	switch capture := b.Capture; capture {
	case "", "both":
		cb.CaptureRequest, cb.CaptureResponse = true, true
	case "request":
		cb.CaptureRequest = true
	case "response":
		cb.CaptureResponse = true
	default:
		return cb, fmt.Errorf("invalid capture %q: must be request, response, or both", capture)
	}

	switch onBinary := b.OnBinary; onBinary {
	case "", "base64":
		cb.OnBinary = "base64"
	case "skip":
		cb.OnBinary = "skip"
	default:
		return cb, fmt.Errorf("invalid on_binary %q: must be base64 or skip", onBinary)
	}

	const defaultMaxBodyBytes = 8192
	cb.MaxRequestBytes = b.MaxRequestBytes
	if cb.MaxRequestBytes <= 0 {
		cb.MaxRequestBytes = defaultMaxBodyBytes
	}
	cb.MaxResponseBytes = b.MaxResponseBytes
	if cb.MaxResponseBytes <= 0 {
		cb.MaxResponseBytes = defaultMaxBodyBytes
	}

	contentTypes := b.ContentTypes
	if len(contentTypes) == 0 {
		contentTypes = DefaultBodyContentTypes
	}
	for _, c := range contentTypes {
		cb.ContentTypes = append(cb.ContentTypes, strings.ToLower(strings.TrimSpace(c)))
	}
	return cb, nil
}

// CompiledACL holds pre-compiled regex patterns for efficient matching.
type CompiledACL struct {
	Whitelist   []*regexp.Regexp
	Blacklist   []*regexp.Regexp
	Passthrough []*regexp.Regexp
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
	trace         CompiledTrace                   // compiled trace configuration
	traceLogger   *slog.Logger                    // nil when trace writes to the main log stream
	traceFile     *os.File                        // underlying trace log file handle for Close()
}

// Update atomically updates the runtime configuration.
// It returns the previous blocked log file (if any) so the caller can close it after releasing the lock.
func (rc *RuntimeConfig) Update(cfg Config, acl CompiledACL, rewrites []CompiledRewriteRule,
	tlsConfig *tls.Config, blockedLogger *slog.Logger, blockedFile *os.File) *os.File {
	// Collect domains that have at least one path-based rule.
	// These domains must be excluded from the exact map so that all their rules
	// are evaluated sequentially (preserving YAML order / first-match-wins).
	// Keys are normalized because lookups come from NormalizeHost; a config
	// author writing "API.Internal" must still match a request for "api.internal".
	domainsWithPath := make(map[string]bool)
	for i := range rewrites {
		if rewrites[i].PathPattern != nil {
			domainsWithPath[NormalizeHost(rewrites[i].Original)] = true
		}
	}

	exactMap := make(map[string]*CompiledRewriteRule)
	for i := range rewrites {
		key := NormalizeHost(rewrites[i].Original)
		if !strings.Contains(key, "*") && !domainsWithPath[key] {
			if _, exists := exactMap[key]; !exists {
				exactMap[key] = &rewrites[i]
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

// SetTrace atomically updates the trace configuration and its log sink.
// It returns the previous trace log file (if any) so the caller can close it
// after releasing the lock, mirroring Update's blocked-log handling.
func (rc *RuntimeConfig) SetTrace(ct CompiledTrace, logger *slog.Logger, file *os.File) *os.File {
	rc.mu.Lock()
	old := rc.traceFile
	rc.trace = ct
	rc.traceLogger = logger
	rc.traceFile = file
	rc.mu.Unlock()
	return old
}

// GetTrace returns the compiled trace config and its dedicated logger.
// The logger is nil when trace output should go to the main log stream.
func (rc *RuntimeConfig) GetTrace() (CompiledTrace, *slog.Logger) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.trace, rc.traceLogger
}

// CloseTraceLog closes the trace log file handle, if open.
func (rc *RuntimeConfig) CloseTraceLog() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.traceFile != nil {
		if err := rc.traceFile.Close(); err != nil {
			slog.Warn("Failed to close trace log file", "err", err)
		}
		rc.traceFile = nil
		rc.traceLogger = nil
	}
}

// OpenTraceLog opens (or creates) the trace log file and returns a JSON logger writing to it.
// If path is empty, the feature uses the main log stream and nil values are returned.
func OpenTraceLog(path string) (*slog.Logger, *os.File, error) {
	if path == "" {
		return nil, nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open trace log: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(f, nil))
	return logger, f, nil
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
	// Compared normalized, so "api.internal" and "API.Internal" are recognized as
	// the same rule rather than silently producing one unreachable duplicate.
	seen := make(map[string]int) // normalized domain -> first index
	for i, rw := range c.Rewrites {
		if rw.PathPattern != "" {
			continue
		}
		key := NormalizeHost(rw.Domain)
		if first, ok := seen[key]; ok {
			return fmt.Errorf("rewrites[%d]: duplicate domain %q without path_pattern (first at rewrites[%d]); second rule is unreachable", i, rw.Domain, first)
		}
		seen[key] = i
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

	// Compile trace rules and validate their log_path parent directory
	if _, err := CompileTrace(cfg.Trace); err != nil {
		return fmt.Errorf("trace: %w", err)
	}
	if cfg.Trace.LogPath != "" {
		dir := filepath.Dir(cfg.Trace.LogPath)
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("trace.log_path: parent directory: %w", err)
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
	for i, p := range cfg.ACL.Passthrough {
		re, err := WildcardToRegex(p)
		if err != nil {
			return CompiledACL{}, fmt.Errorf("invalid passthrough pattern[%d] %q: %w", i, p, err)
		}
		c.Passthrough = append(c.Passthrough, re)
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

// NormalizeHost canonicalises a hostname for policy matching.
//
// DNS names are case-insensitive and a trailing dot denotes the same FQDN, so
// "EVIL.example.com" and "evil.example.com." address exactly the host that
// "evil.example.com" does. Matching the raw value would let either form slip
// past a blacklist, or miss a rewrite rule and leak the request to public DNS.
// Every policy decision must compare normalized values on both sides.
func NormalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// WildcardToRegex converts a domain pattern with wildcards to a regex.
//
// Patterns are matched against hosts normalized by [NormalizeHost], so pattern
// literals are lowercased here to keep both sides consistent. Raw regex
// patterns are the caller's responsibility: they are compiled case-sensitively
// and are not lowercased, since a user-supplied regex may intentionally use
// character classes.
//
// Supports:
//   - Exact match: "example.com" -> "^example\.com$"
//   - Wildcard: "*.example.com" -> "^.+\.example\.com$" (matches any subdomain depth)
//   - Full wildcard: "*" -> ".*"
//   - Raw regex: "~<regex>" -> compiled case-insensitively, anchored if not already
func WildcardToRegex(pattern string) (*regexp.Regexp, error) {
	if strings.HasPrefix(pattern, "~") {
		return compileRawRegex(pattern[1:])
	}

	if pattern == "*" {
		return regexp.Compile(".*")
	}

	// Escape regex special characters except *. Lowercase first: hosts are
	// normalized before matching, so an uppercase pattern would never match.
	escaped := regexp.QuoteMeta(strings.ToLower(pattern))

	// Replace \* with appropriate regex
	// *.example.com -> matches any subdomain depth (e.g. a.b.c.example.com)
	if strings.HasPrefix(escaped, `\*\.`) {
		escaped = `.+\.` + escaped[4:]
	}

	// Anchor the pattern, and compile case-insensitively. Callers normalize hosts
	// via NormalizeHost before matching, so (?i) is redundant on that path — it is
	// here so a future call site that forgets to normalize fails closed (still
	// matching the blacklist) rather than open.
	escaped = "(?i)^" + escaped + "$"

	return regexp.Compile(escaped)
}

// compileRawRegex compiles a user-supplied "~" pattern.
//
// Two adjustments make raw patterns behave like the wildcard forms:
//
// Case-insensitive, because hosts are lowercased by [NormalizeHost] before
// matching, so a raw pattern containing uppercase would silently never match.
//
// Anchored, because Match uses MatchString, which succeeds on any substring.
// Unanchored, "~api\.corp\.com" would match "api.corp.com.attacker.net" — a
// whitelist entry that fails open, and a rewrite that captures unintended hosts
// along with that rule's injected headers. Wrapping in a non-capturing group
// keeps alternations intact and is a no-op for already-anchored patterns.
func compileRawRegex(expr string) (*regexp.Regexp, error) {
	// Validate the user's expression first so errors point at what they wrote.
	if _, err := regexp.Compile(expr); err != nil {
		return nil, err
	}
	return regexp.Compile("(?i)^(?:" + expr + ")$")
}

// WildcardToURLRegex compiles a pattern intended to match a full request URL
// (scheme://host/path?query) rather than a bare hostname.
//
// It differs from [WildcardToRegex] in one way: raw "~" patterns are left
// unanchored. Matching a substring of a URL is the intended semantic for trace
// rules — "~/v1/debug" should select that path on any host — whereas anchoring
// a host pattern is what stops a whitelist entry from matching
// "api.corp.com.attacker.net". URL patterns select what to observe and grant no
// access, so the fail-open concern that motivates anchoring does not apply.
func WildcardToURLRegex(pattern string) (*regexp.Regexp, error) {
	if strings.HasPrefix(pattern, "~") {
		expr := pattern[1:]
		if _, err := regexp.Compile(expr); err != nil {
			return nil, err
		}
		return regexp.Compile("(?i)" + expr)
	}
	return WildcardToRegex(pattern)
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

// ReloadIgnoredFields returns the names of settings that differ between the
// running config and a newly loaded one but which SIGHUP cannot apply.
//
// The reload rebuilds ACL, rewrites, trace rules, log files, the outbound TLS
// config and the transport pool. It cannot rebuild anything captured once at
// startup: the MITM CA is loaded into package state before the CONNECT handler
// closes over it, the leaf-signing TLSConfig (including mitm_org) is built once
// and its certificate cache outlives the reload, and the listen ports are baked
// into the constructed http.Servers.
//
// Silently accepting a value that is never applied is the failure this guards
// against. Rotating an expiring MITM CA, sending SIGHUP and seeing
// "Configuration reloaded successfully" would otherwise leave the proxy signing
// leaves with the old CA until restart.
func ReloadIgnoredFields(oldCfg, newCfg Config) []string {
	var changed []string

	type field struct {
		name     string
		old, new string
	}
	for _, f := range []field{
		{"proxy.port", oldCfg.Proxy.Port, newCfg.Proxy.Port},
		{"proxy.metrics_port", oldCfg.Proxy.MetricsPort, newCfg.Proxy.MetricsPort},
		{"proxy.mitm_cert_path", oldCfg.Proxy.MitmCertPath, newCfg.Proxy.MitmCertPath},
		{"proxy.mitm_key_path", oldCfg.Proxy.MitmKeyPath, newCfg.Proxy.MitmKeyPath},
		{"proxy.mitm_keystore_path", oldCfg.Proxy.MitmKeystorePath, newCfg.Proxy.MitmKeystorePath},
		{"proxy.mitm_keystore_password", oldCfg.Proxy.MitmKeystorePassword, newCfg.Proxy.MitmKeystorePassword},
		{"proxy.mitm_org", oldCfg.Proxy.MitmOrg, newCfg.Proxy.MitmOrg},
	} {
		if f.old != f.new {
			changed = append(changed, f.name)
		}
	}
	return changed
}
