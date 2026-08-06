// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"net/http"
	"testing"

	"go-egress-proxy/internal/config"
)

// runtimeFor builds a RuntimeConfig from a raw Config, compiling ACL and rewrites
// the same way main does, so tests exercise the real compilation path.
func runtimeFor(t *testing.T, cfg config.Config) *config.RuntimeConfig {
	t.Helper()

	acl, err := config.CompileACL(cfg)
	if err != nil {
		t.Fatalf("CompileACL: %v", err)
	}
	rewrites, err := config.CompileRewrites(cfg.Rewrites)
	if err != nil {
		t.Fatalf("CompileRewrites: %v", err)
	}
	rc := &config.RuntimeConfig{}
	_ = rc.Update(cfg, acl, rewrites, nil, nil, nil)
	return rc
}

// actionFor drives the real HandleRequest and reports whether the request was
// blocked (a non-nil response means the policy engine short-circuited it).
func actionFor(t *testing.T, rc *config.RuntimeConfig, rawURL string) (blocked bool) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, resp := HandleRequest(req, nil, rc)
	if resp != nil {
		resp.Body.Close() //nolint:errcheck // test cleanup
		return true
	}
	return false
}

// TestBlacklistIsCaseAndTrailingDotInsensitive pins the egress-control bypass:
// DNS names are case-insensitive and a trailing dot denotes the same FQDN, so
// every spelling of a blacklisted host must be blocked.
func TestBlacklistIsCaseAndTrailingDotInsensitive(t *testing.T) {
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW" // documented denylist deployment
	cfg.ACL.Blacklist = []string{"evil.example.com", "*.bad.example.com"}

	rc := runtimeFor(t, cfg)

	blocked := []string{
		"https://evil.example.com/x",
		"https://EVIL.example.com/x",
		"https://Evil.Example.Com/x",
		"https://evil.example.com./x",
		"https://EVIL.EXAMPLE.COM./x",
		"https://sub.bad.example.com/x",
		"https://SUB.BAD.example.com./x",
	}
	for _, u := range blocked {
		t.Run(u, func(t *testing.T) {
			if !actionFor(t, rc, u) {
				t.Errorf("%s reached upstream; every spelling of a blacklisted host must be blocked", u)
			}
		})
	}

	// Guard against over-matching: a genuinely different host must still pass.
	if actionFor(t, rc, "https://good.example.com/x") {
		t.Error("good.example.com was blocked; normalization must not widen the blacklist")
	}
}

// TestRewriteMatchesRegardlessOfHostSpelling pins the inverse failure: a missed
// rewrite silently drops the split-brain redirect and its injected headers, and
// sends the request out over public DNS instead.
func TestRewriteMatchesRegardlessOfHostSpelling(t *testing.T) {
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"
	cfg.Rewrites = []config.RewriteRule{
		{
			Domain:   "API.Internal", // deliberately mixed-case in config
			TargetIP: "10.0.0.1",
			Headers:  map[string]string{"X-Injected": "yes"},
		},
	}

	rc := runtimeFor(t, cfg)

	for _, host := range []string{"api.internal", "API.Internal", "api.internal.", "API.INTERNAL."} {
		t.Run(host, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+"/v1", nil)
			if err != nil {
				t.Fatal(err)
			}
			resultReq, resp := HandleRequest(req, nil, rc)
			if resp != nil {
				resp.Body.Close() //nolint:errcheck // test cleanup
				t.Fatalf("%s was blocked; the rewrite rule should have matched", host)
			}
			rw, ok := resultReq.Context().Value(config.RewriteCtxKey).(RewriteResult)
			if !ok {
				t.Fatalf("%s: no RewriteResult on context; request would go out over public DNS", host)
			}
			if rw.TargetIP != "10.0.0.1" {
				t.Errorf("TargetIP = %q, want 10.0.0.1", rw.TargetIP)
			}
			if got := resultReq.Header.Get("X-Injected"); got != "yes" {
				t.Errorf("X-Injected = %q, want yes; injected headers were dropped", got)
			}
		})
	}
}

// TestRawRegexPatternsAreAnchored pins the fail-open whitelist: MatchString is
// substring-based, so an unanchored "~" pattern would match an attacker-suffixed
// host.
func TestRawRegexPatternsAreAnchored(t *testing.T) {
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"
	cfg.ACL.Whitelist = []string{`~api\.corp\.com`}

	rc := runtimeFor(t, cfg)

	if actionFor(t, rc, "https://api.corp.com/x") {
		t.Error("api.corp.com was blocked; the whitelist entry should match it")
	}
	for _, u := range []string{
		"https://api.corp.com.attacker.net/x",
		"https://evil-api.corp.com.attacker.net/x",
	} {
		if !actionFor(t, rc, u) {
			t.Errorf("%s was allowed; raw regex whitelist entries must be anchored", u)
		}
	}
}

// TestRawRegexIsCaseInsensitive complements the anchoring test: hosts are
// lowercased before matching, so an uppercase raw pattern must still match.
func TestRawRegexIsCaseInsensitive(t *testing.T) {
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW"
	cfg.ACL.Blacklist = []string{`~EVIL\.example\.com`}

	rc := runtimeFor(t, cfg)

	for _, u := range []string{"https://evil.example.com/x", "https://EVIL.example.com/x"} {
		if !actionFor(t, rc, u) {
			t.Errorf("%s was allowed; raw patterns must match case-insensitively", u)
		}
	}
}

// TestRawRegexAlternationSurvivesAnchoring guards the anchoring wrapper: a bare
// "^...$" wrap would change the meaning of a top-level alternation.
func TestRawRegexAlternationSurvivesAnchoring(t *testing.T) {
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW"
	cfg.ACL.Blacklist = []string{`~one\.example\.com|two\.example\.com`}

	rc := runtimeFor(t, cfg)

	for _, u := range []string{"https://one.example.com/x", "https://two.example.com/x"} {
		if !actionFor(t, rc, u) {
			t.Errorf("%s was allowed; both alternation branches must stay anchored and matching", u)
		}
	}
	if actionFor(t, rc, "https://three.example.com/x") {
		t.Error("three.example.com was blocked; it matches neither alternation branch")
	}
}

// TestDecideConnectRejectsOnlyUninspectableTunnels pins which hosts are refused
// at CONNECT time and which are intercepted instead.
//
// Rejection exists for one case: a host that would be tunneled without
// interception. Passthrough returns ConnectAccept and never reaches
// HandleRequest, so a passthrough pattern overlapping a blacklist entry would
// hand out an uninspected tunnel to a denied host.
//
// A blacklisted host that is *not* passthrough is still MITM'd. Nothing is
// forwarded upstream before HandleRequest applies policy, so it is blocked
// either way -- but the client gets a readable 403 instead of a rejected
// CONNECT, which Go surfaces as an opaque transport error.
func TestDecideConnectRejectsOnlyUninspectableTunnels(t *testing.T) {
	cfg := config.Config{}
	cfg.ACL.Blacklist = []string{"leaked.vault.internal", "evil.example.com"}
	cfg.ACL.Passthrough = []string{"*.vault.internal"} // the README's recommended shape

	acl, err := config.CompileACL(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host string
		want ConnectDecision
	}{
		{"leaked.vault.internal", ConnectReject},  // passthrough + blacklist: must not tunnel
		{"LEAKED.Vault.Internal", ConnectReject},  // and regardless of spelling
		{"ok.vault.internal", ConnectPassthrough}, // passthrough only
		{"evil.example.com", ConnectMITM},         // blacklisted, but inspectable: 403 via HandleRequest
		{"api.example.com", ConnectMITM},          // neither
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := DecideConnect(config.NormalizeHost(tt.host), acl); got != tt.want {
				t.Errorf("DecideConnect(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// TestBlacklistOutranksRewrite pins the precedence that no test configured
// before: a host present in both the rewrite table and the blacklist.
//
// Rewrites otherwise bypass the ACL by design. That is fine for the whitelist
// and the default policy, but a denylist is not a preference — the host was
// being forwarded to its target_ip with the rule's injected headers. Over HTTPS
// this was unreachable only because DecideConnect rejected blacklisted hosts at
// CONNECT time; narrowing that check removed the backstop and nothing in the
// suite noticed, because no fixture put a host in both tables.
func TestBlacklistOutranksRewrite(t *testing.T) {
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"
	cfg.ACL.Blacklist = []string{"metadata.google.internal", "*.evil.example.com"}
	cfg.Rewrites = []config.RewriteRule{
		{
			Domain:   "metadata.google.internal",
			TargetIP: "169.254.169.254",
			Headers:  map[string]string{"X-Injected": "s3cr3t"},
		},
		{
			Domain:   "*.evil.example.com",
			TargetIP: "10.0.0.9",
			Headers:  map[string]string{"X-Injected": "s3cr3t"},
		},
		{
			Domain:   "ok.example.com",
			TargetIP: "10.0.0.1",
			Headers:  map[string]string{"X-Injected": "fine"},
		},
	}

	rc := runtimeFor(t, cfg)

	for _, host := range []string{"metadata.google.internal", "sub.evil.example.com"} {
		t.Run(host, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+"/x", nil)
			if err != nil {
				t.Fatal(err)
			}
			out, resp := HandleRequest(req, nil, rc)
			if resp == nil {
				rw, _ := out.Context().Value(config.RewriteCtxKey).(RewriteResult)
				t.Fatalf("blacklisted host was forwarded to %q with X-Injected=%q",
					rw.TargetIP, out.Header.Get("X-Injected"))
			}
			resp.Body.Close() //nolint:errcheck // test cleanup

			if _, ok := out.Context().Value(config.RewriteCtxKey).(RewriteResult); ok {
				t.Error("a rewrite target was attached to a blacklisted request")
			}
			if got := out.Header.Get("X-Injected"); got != "" {
				t.Errorf("X-Injected = %q; a blacklisted request must not receive injected headers", got)
			}
		})
	}

	// A rewrite that is not blacklisted must still apply.
	t.Run("unblacklisted rewrite still applies", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://ok.example.com/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		out, resp := HandleRequest(req, nil, rc)
		if resp != nil {
			resp.Body.Close() //nolint:errcheck // test cleanup
			t.Fatal("a non-blacklisted rewrite was blocked")
		}
		rw, ok := out.Context().Value(config.RewriteCtxKey).(RewriteResult)
		if !ok || rw.TargetIP != "10.0.0.1" {
			t.Errorf("rewrite did not apply: %+v", rw)
		}
	})
}

// TestBlacklistWinsOverWhitelistOnRequestPath pins the precedence governing all
// plain HTTP and every intercepted HTTPS request.
//
// The CONNECT-stage ordering has a test; this one did not, and every ACL fixture
// in the suite used disjoint lists, so no test configured a host matched by
// both. Swapping the two branches in HandleRequest left every package green.
// The configuration that breaks is the one the README recommends: a broad
// whitelist with a narrower blacklist carved out of it.
func TestBlacklistWinsOverWhitelistOnRequestPath(t *testing.T) {
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"
	cfg.ACL.Whitelist = []string{"*.corp.internal", "shared.example.com"}
	cfg.ACL.Blacklist = []string{"secrets.corp.internal", "shared.example.com"}

	rc := runtimeFor(t, cfg)

	tests := []struct {
		name        string
		url         string
		wantBlocked bool
	}{
		{
			name:        "narrow blacklist carved out of a broad whitelist",
			url:         "https://secrets.corp.internal/x",
			wantBlocked: true,
		},
		{
			name:        "same host in both lists",
			url:         "https://shared.example.com/x",
			wantBlocked: true,
		},
		{
			name:        "whitelisted host not in the blacklist still passes",
			url:         "https://build.corp.internal/x",
			wantBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := actionFor(t, rc, tt.url); got != tt.wantBlocked {
				t.Errorf("blocked = %v, want %v — blacklist must be evaluated before whitelist", got, tt.wantBlocked)
			}
		})
	}
}
