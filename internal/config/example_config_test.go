// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-egress-proxy/internal/config"
)

// exampleConfigPath is the file the Quick Start tells users to copy. It is
// documentation that executes, so it gets tested like code.
const exampleConfigPath = "../../doc/examples/configuration.yaml"

// withoutProxyEnv clears every PROXY_* override for the duration of the test.
//
// LoadConfig applies environment overrides, so these tests otherwise depend on
// the developer's shell: exporting PROXY_MITM_KEYSTORE_PATH (a normal thing to
// do when running the proxy with a PKCS#12 keystore) makes the example config
// fail the mutually-exclusive check, and PROXY_DEFAULT_POLICY with an
// unexpected value fails validation. Neither has anything to do with what is
// being asserted, so the environment is removed rather than reasoned about.
//
// The list is derived from os.Environ() instead of being written out, so a
// PROXY_* variable added later is covered without anyone remembering to update
// this. Every override is read with os.Getenv(...) != "", so setting a variable
// to the empty string is equivalent to unsetting it; t.Setenv restores the
// original value when the test ends.
func withoutProxyEnv(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		if key, _, found := strings.Cut(entry, "="); found && strings.HasPrefix(key, "PROXY_") {
			t.Setenv(key, "")
		}
	}
}

// TestExampleConfigLoads guards against the example drifting out of sync with
// the loader — a shipped config that fails Validate() breaks the first thing a
// new user does.
func TestExampleConfigLoads(t *testing.T) {
	withoutProxyEnv(t)

	if _, err := config.LoadConfig(filepath.Clean(exampleConfigPath)); err != nil {
		t.Fatalf("shipped example config does not load: %v", err)
	}
}

// TestExampleBlacklistDoesNotFailOpen pins the semantics of every denylist entry
// in the example.
//
// The raw-regex entry previously read "~social-media\.internal  # matches as
// substring". Raw patterns are anchored, so it matched that exact host and
// nothing else, and the comment invited users to copy the idiom into their own
// denylists — where subdomains would sail straight through. A denylist example
// that fails open is worse than no example.
func TestExampleBlacklistDoesNotFailOpen(t *testing.T) {
	withoutProxyEnv(t)

	cfg, err := config.LoadConfig(filepath.Clean(exampleConfigPath))
	if err != nil {
		t.Fatalf("load example config: %v", err)
	}
	acl, err := config.CompileACL(cfg)
	if err != nil {
		t.Fatalf("compile example ACL: %v", err)
	}

	blocked := []string{
		"social-media.internal",
		"ads.social-media.internal",
		"deep.nested.social-media.internal",
		"SOCIAL-MEDIA.INTERNAL",
		// A wildcard entry does not cover the apex; the example must list both.
		"www.tiktok.com",
		"tiktok.com",
		"facebook.com",
		"twitter.com",
	}
	for _, host := range blocked {
		if !config.Matches(config.NormalizeHost(host), acl.Blacklist) {
			t.Errorf("%q is not blocked by the example blacklist", host)
		}
	}

	// The anchoring has to cut both ways, or the entry becomes a substring match
	// that blocks unrelated hosts.
	allowed := []string{
		"social-media.internal.evil.com",
		"notsocial-media.internal",
		"social-media.internalx",
	}
	for _, host := range allowed {
		if config.Matches(config.NormalizeHost(host), acl.Blacklist) {
			t.Errorf("%q is blocked by the example blacklist but should not be", host)
		}
	}
}
