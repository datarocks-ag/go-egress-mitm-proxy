// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// envVarPattern finds PROXY_* environment variable names in source and prose.
var envVarPattern = regexp.MustCompile(`PROXY_[A-Z0-9_]+`)

// sourcesDeclaringEnvVars are the files that read PROXY_* variables.
var sourcesDeclaringEnvVars = []string{
	"../../internal/config/config.go",
	"../../cmd/mitm-proxy/main.go",
}

// docsDocumentingEnvVars must mention every variable the code reads.
var docsDocumentingEnvVars = []string{
	"../../README.md",
	"../../doc/architecture.md",
}

// TestEveryEnvVarIsDocumented catches documentation drift mechanically.
//
// Both PROXY_MITM_ORG and PROXY_PRESTOP_GRACE were honored by the binary while
// missing from doc/architecture.md's override list. An undocumented knob is an
// operational trap: the only way to discover it is to read the source. Reviews
// keep missing this because the code and the prose live in different files, so
// the check belongs in the test suite rather than in a checklist.
func TestEveryEnvVarIsDocumented(t *testing.T) {
	declared := map[string]bool{}
	for _, src := range sourcesDeclaringEnvVars {
		body, err := os.ReadFile(filepath.Clean(src))
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		for _, name := range envVarPattern.FindAllString(string(body), -1) {
			declared[name] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("found no PROXY_* variables in the sources; the scan is broken, not the docs")
	}

	for _, doc := range docsDocumentingEnvVars {
		body, err := os.ReadFile(filepath.Clean(doc))
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		text := string(body)

		var missing []string
		for name := range declared {
			if !strings.Contains(text, name) {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s does not document: %s", doc, strings.Join(missing, ", "))
		}
	}
}
