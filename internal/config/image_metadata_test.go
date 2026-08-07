// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requiredImageLabels are the OCI annotations the published container must
// carry. Registries read these directly: ghcr showed "No description provided"
// for a release because the description was absent, and `source` is what links
// a pulled image back to the commit that produced it.
var requiredImageLabels = []string{
	"org.opencontainers.image.title",
	"org.opencontainers.image.description",
	"org.opencontainers.image.source",
	"org.opencontainers.image.url",
	"org.opencontainers.image.documentation",
	"org.opencontainers.image.licenses",
	"org.opencontainers.image.vendor",
	"org.opencontainers.image.version",
	"org.opencontainers.image.revision",
	"org.opencontainers.image.created",
}

// TestDockerfileDeclaresImageMetadata keeps the image self-describing when it is
// built outside CI.
//
// The workflow's metadata action supplies most of these, so dropping them from
// the Dockerfile would go unnoticed in the published artifact while every local
// `make docker-build` produced an anonymous image. The Dockerfile is the copy
// that is reviewable in a diff; the action's description in particular used to
// come from the GitHub repository description, a settings field nothing in the
// tree points at.
func TestDockerfileDeclaresImageMetadata(t *testing.T) {
	body, err := os.ReadFile(filepath.Clean("../../Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	text := string(body)

	for _, label := range requiredImageLabels {
		if !strings.Contains(text, label) {
			t.Errorf("Dockerfile does not declare %s", label)
		}
	}
}

// TestPerBuildLabelsComeFromBuildArgs pins that version, revision and creation
// time are injected rather than baked in.
//
// A hardcoded value is worse than none: it looks authoritative and is wrong for
// every build after the one it was written for, so an operator correlating a
// running container with a commit gets a confident wrong answer.
func TestPerBuildLabelsComeFromBuildArgs(t *testing.T) {
	body, err := os.ReadFile(filepath.Clean("../../Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	text := string(body)

	for arg, label := range map[string]string{
		"VERSION":  "org.opencontainers.image.version",
		"REVISION": "org.opencontainers.image.revision",
		"CREATED":  "org.opencontainers.image.created",
	} {
		if !strings.Contains(text, "ARG "+arg) {
			t.Errorf("Dockerfile has no ARG %s", arg)
		}
		if !strings.Contains(text, label+"=\"${"+arg+"}\"") {
			t.Errorf("%s is not wired to ${%s}; a hardcoded value would be wrong for every "+
				"build after the one it was written for", label, arg)
		}
	}
}

// TestReleaseWorkflowPassesBuildMetadata: the Dockerfile defaults are
// placeholders, so CI has to override them or every published image claims
// revision "unknown".
func TestReleaseWorkflowPassesBuildMetadata(t *testing.T) {
	body, err := os.ReadFile(filepath.Clean("../../.github/workflows/release.yaml"))
	if err != nil {
		t.Fatalf("read release.yaml: %v", err)
	}
	text := string(body)

	for _, arg := range []string{"VERSION=", "REVISION=", "CREATED="} {
		if !strings.Contains(text, arg) {
			t.Errorf("release workflow does not pass the %s build arg", arg)
		}
	}
	// The description must be set explicitly: metadata-action derives it from the
	// GitHub repository description, which is empty, and an empty value overrides
	// the Dockerfile's.
	if !strings.Contains(text, "org.opencontainers.image.description=") {
		t.Error("release workflow does not set the image description explicitly; " +
			"metadata-action will emit an empty one and the registry shows " +
			"\"No description provided\"")
	}
}
