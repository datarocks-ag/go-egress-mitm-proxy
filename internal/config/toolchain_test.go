// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDockerfileMatchesGoMod keeps the shipped image on the toolchain the tests
// run against.
//
// The Dockerfile built with golang:1.26-alpine while go.mod declared 1.25.0 and
// every workflow pinned 1.25. The `go` directive fixes the language version, not
// the linked standard library, so the container and the release binaries linked
// a different crypto/tls, net/http and hijacked-connection implementation from
// the one the unit tests exercised — in a proxy whose behavior depends closely
// on all three.
//
// The workflows now read go.mod via `go-version-file`, so this is the one
// remaining place a version is written by hand.
func TestDockerfileMatchesGoMod(t *testing.T) {
	goMod, err := os.ReadFile(filepath.Clean("../../go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	m := regexp.MustCompile(`(?m)^go (\d+)\.(\d+)`).FindStringSubmatch(string(goMod))
	if m == nil {
		t.Fatal("no go directive in go.mod")
	}
	wantMajorMinor := m[1] + "." + m[2]

	dockerfile, err := os.ReadFile(filepath.Clean("../../Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	d := regexp.MustCompile(`FROM golang:(\d+\.\d+)`).FindStringSubmatch(string(dockerfile))
	if d == nil {
		t.Fatal("no golang base image in Dockerfile")
	}

	if d[1] != wantMajorMinor {
		t.Errorf("Dockerfile builds with Go %s but go.mod declares %s; the shipped image would "+
			"link a different stdlib from the one the tests run against", d[1], wantMajorMinor)
	}
}

// TestWorkflowsReadTheToolchainFromGoMod stops a hardcoded version reappearing.
func TestWorkflowsReadTheToolchainFromGoMod(t *testing.T) {
	for _, wf := range []string{"../../.github/workflows/ci.yaml", "../../.github/workflows/release.yaml"} {
		body, err := os.ReadFile(filepath.Clean(wf))
		if err != nil {
			t.Fatalf("read %s: %v", wf, err)
		}
		text := string(body)
		if !strings.Contains(text, "go-version-file: go.mod") {
			t.Errorf("%s does not read the toolchain from go.mod", wf)
		}
		if regexp.MustCompile(`go-version:\s*'`).MatchString(text) {
			t.Errorf("%s pins a Go version by hand; it will drift from go.mod", wf)
		}
	}
}
