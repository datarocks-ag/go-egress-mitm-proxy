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

// TestEveryConfigFieldAppearsInTheExample keeps the shipped example the complete
// discovery surface for configuration.
//
// The example is what the Quick Start tells users to copy, and for most operators
// it is the only place they will learn an option exists. Three separate options
// have now been added with the example left untouched — PROXY_MAX_CONNECTIONS,
// its max_connections YAML field, and mitm_org — each discoverable only by
// reading the source. Reviews keep missing it because the field and the example
// live in different files, so the check belongs here.
//
// Fields may be commented out in the example; this asserts they are mentioned,
// not enabled.
func TestEveryConfigFieldAppearsInTheExample(t *testing.T) {
	source, err := os.ReadFile(filepath.Clean("config.go"))
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	fields := regexp.MustCompile(`yaml:"([a-z_0-9]+)"`).FindAllStringSubmatch(string(source), -1)
	if len(fields) == 0 {
		t.Fatal("found no yaml tags; the scan is broken, not the example")
	}

	example, err := os.ReadFile(filepath.Clean(exampleConfigPath))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	text := string(example)

	var missing []string
	seen := map[string]bool{}
	for _, f := range fields {
		name := f[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		if !strings.Contains(text, name) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%s does not mention: %s\n(an option absent from the example is discoverable "+
			"only by reading the source)", exampleConfigPath, strings.Join(missing, ", "))
	}
}
