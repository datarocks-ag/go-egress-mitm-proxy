// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package trace

import (
	"net/http"
	"strings"
	"testing"

	"go-egress-proxy/internal/config"
)

// redactorFor compiles a trace config with the given redact_headers list.
func redactorFor(t *testing.T, redact []string) Redactor {
	t.Helper()
	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled:       true,
		RedactHeaders: redact,
		Rules:         []config.TraceRule{{Host: "*"}},
	})
	if err != nil {
		t.Fatalf("compile trace config: %v", err)
	}
	return NewRedactor(ct)
}

// TestRedactHeadersMinusPrefixUnmasksOneDefault is the point of the feature.
//
// Before it, the only way to see a masked header was log_secrets: true, which
// disables redaction entirely. An operator who needed Location to follow a
// redirect chain had to give up the masking of Authorization and Cookie to get
// it — an all-or-nothing escape hatch that invites reaching for the widest
// setting to solve the narrowest problem.
func TestRedactHeadersMinusPrefixUnmasksOneDefault(t *testing.T) {
	rd := redactorFor(t, []string{"-location"})

	hdr := http.Header{}
	hdr.Set("Location", "https://app.internal.com/callback?code=visible")
	hdr.Set("Authorization", "Bearer still-secret")
	hdr.Set("Cookie", "session=still-secret")
	hdr.Set("Referer", "https://app.internal.com/login?session=still-secret")

	got := rd.headerMap(hdr)

	if !strings.Contains(got["Location"], "code=visible") {
		t.Errorf("Location = %q, want it unmasked: that is what \"-location\" asks for", got["Location"])
	}
	// Everything else must keep its masking; the whole point is that this is a
	// scalpel rather than log_secrets.
	for _, name := range []string{"Authorization", "Cookie", "Referer"} {
		if strings.Contains(got[name], "still-secret") {
			t.Errorf("%s = %q leaked; removing one default must not disable the others", name, got[name])
		}
	}
}

// TestRedactHeadersAddAndRemoveCompose covers the two forms together, and that
// later entries win.
func TestRedactHeadersAddAndRemoveCompose(t *testing.T) {
	rd := redactorFor(t, []string{"X-Api-Key", "-referer", "-location", "location"})

	hdr := http.Header{}
	hdr.Set("X-Api-Key", "secret-key")
	hdr.Set("Referer", "https://app/login?session=abc")
	hdr.Set("Location", "https://app/cb?code=xyz")

	got := rd.headerMap(hdr)

	if strings.Contains(got["X-Api-Key"], "secret-key") {
		t.Errorf("X-Api-Key = %q, want masked by the plain entry", got["X-Api-Key"])
	}
	if !strings.Contains(got["Referer"], "session=abc") {
		t.Errorf("Referer = %q, want unmasked by \"-referer\"", got["Referer"])
	}
	if strings.Contains(got["Location"], "code=xyz") {
		t.Errorf("Location = %q, want re-masked: \"location\" follows \"-location\"", got["Location"])
	}
}

// TestRedactHeadersRemovalIsCaseAndSpaceInsensitive matches how the plain form
// already behaves, so the two do not diverge.
func TestRedactHeadersRemovalIsCaseAndSpaceInsensitive(t *testing.T) {
	rd := redactorFor(t, []string{"  -LOCATION  "})

	hdr := http.Header{}
	hdr.Set("Location", "https://app/cb?code=visible")
	if !strings.Contains(rd.headerMap(hdr)["Location"], "code=visible") {
		t.Error("\"  -LOCATION  \" did not unmask Location; the removal form must normalize " +
			"like the add form")
	}
}

// TestLogSecretsStillOverridesEverything: the coarse hatch is unchanged.
func TestLogSecretsStillOverridesEverything(t *testing.T) {
	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled:    true,
		LogSecrets: true,
		Rules:      []config.TraceRule{{Host: "*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer verbatim")
	if !strings.Contains(NewRedactor(ct).headerMap(hdr)["Authorization"], "verbatim") {
		t.Error("log_secrets no longer disables redaction")
	}
}
