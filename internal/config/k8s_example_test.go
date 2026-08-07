// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"go-egress-proxy/internal/config"
)

const k8sConfigMapPath = "../../doc/k8s/go-egress-proxy-configmap"

// TestKubernetesConfigMapIsValid loads the config embedded in the example
// ConfigMap and runs it through the real loader.
//
// This manifest has shipped broken before: it mounted the config at a path the
// container does not read, so the proxy exited 1 on start. A manifest is only
// documentation until someone applies it, at which point a mistake costs a
// crash-looping pod — and nothing in the build had ever looked at the config
// inside it.
func TestKubernetesConfigMapIsValid(t *testing.T) {
	withoutProxyEnv(t)

	raw, err := os.ReadFile(filepath.Clean(k8sConfigMapPath))
	if err != nil {
		t.Fatalf("read ConfigMap: %v", err)
	}

	var manifest struct {
		Data map[string]string `yaml:"data"`
	}
	if err = yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("ConfigMap is not valid YAML: %v", err)
	}

	embedded, ok := manifest.Data["config.yaml"]
	if !ok {
		t.Fatal(`ConfigMap has no data["config.yaml"] key`)
	}

	// LoadConfig is the path the binary takes, so validation, defaulting and
	// pattern compilation are all exercised rather than approximated.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, []byte(embedded), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("config embedded in the example ConfigMap does not load: %v", err)
	}
	if _, err := config.CompileACL(cfg); err != nil {
		t.Fatalf("compile ACL from the example ConfigMap: %v", err)
	}
	if _, err := config.CompileRewrites(cfg.Rewrites); err != nil {
		t.Fatalf("compile rewrites from the example ConfigMap: %v", err)
	}
}

// TestKubernetesManifestsMountConfigWhereTheBinaryReadsIt pins the specific
// mistake that made the sidecar crash-loop: the Deployment mounted the config
// at a path unrelated to the CONFIG_PATH the image sets.
func TestKubernetesManifestsMountConfigWhereTheBinaryReadsIt(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean("../../doc/k8s/go-egress-proxy-deployment"))
	if err != nil {
		t.Fatalf("read Deployment: %v", err)
	}

	var manifest struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name         string `yaml:"name"`
						VolumeMounts []struct {
							Name      string `yaml:"name"`
							MountPath string `yaml:"mountPath"`
						} `yaml:"volumeMounts"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("Deployment is not valid YAML: %v", err)
	}

	// Must match CONFIG_PATH in the Dockerfile.
	const wantMountPath = "/app/config.yaml"

	var found bool
	for _, c := range manifest.Spec.Template.Spec.Containers {
		if c.Name != "mitm-proxy" {
			continue
		}
		for _, m := range c.VolumeMounts {
			if m.Name == "config" {
				found = true
				if m.MountPath != wantMountPath {
					t.Errorf("config mounted at %q, but the image reads %q", m.MountPath, wantMountPath)
				}
			}
		}
	}
	if !found {
		t.Error("no config volumeMount on the mitm-proxy container")
	}
}

// TestKubernetesExampleGatesBothSchemes pins that the app container is pointed
// at the proxy for cleartext HTTP as well as HTTPS.
//
// The manifest previously set only HTTPS_PROXY. Every proxy-aware client selects
// by request scheme, so all plain-HTTP egress went direct: no ACL evaluation, no
// 403, no blocked-log entry, no metric. The manifest read as "all egress is
// gated" while the entire cleartext surface was not — and the proxy explicitly
// supports that path.
func TestKubernetesExampleGatesBothSchemes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean("../../doc/k8s/go-egress-proxy-deployment"))
	if err != nil {
		t.Fatalf("read Deployment: %v", err)
	}

	var manifest struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name string `yaml:"name"`
						Env  []struct {
							Name  string `yaml:"name"`
							Value string `yaml:"value"`
						} `yaml:"env"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	if err = yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("Deployment is not valid YAML: %v", err)
	}

	var app *struct {
		Name string `yaml:"name"`
		Env  []struct {
			Name  string `yaml:"name"`
			Value string `yaml:"value"`
		} `yaml:"env"`
	}
	for i, c := range manifest.Spec.Template.Spec.Containers {
		if c.Name == "app" {
			app = &manifest.Spec.Template.Spec.Containers[i]
		}
	}
	if app == nil {
		t.Fatal("no container named \"app\" in the example Deployment")
	}

	env := map[string]string{}
	for _, e := range app.Env {
		env[e.Name] = e.Value
	}

	// Lowercase matters: curl and several libraries read only those spellings.
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if env[key] == "" {
			t.Errorf("app container does not set %s; egress for that scheme bypasses the proxy entirely", key)
		}
	}

	// All four must point at the same place. A lowercase variant pointing
	// elsewhere is worse than one being absent: the client silently picks a
	// different proxy for the same traffic depending on which spelling it reads.
	want := env["HTTP_PROXY"]
	for _, key := range []string{"HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if env[key] != want {
			t.Errorf("%s = %q but HTTP_PROXY = %q; the spellings disagree about where traffic goes",
				key, env[key], want)
		}
	}

	// NO_PROXY keeps in-cluster and link-local traffic off the proxy. Without it
	// pod-to-pod and metadata-endpoint calls are tunneled through the sidecar,
	// where the ACL has no rules for them -- with default_policy BLOCK that breaks
	// service discovery, and it puts the proxy on the path of traffic it was
	// never meant to see.
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		if env[key] == "" {
			t.Errorf("app container does not set %s; in-cluster traffic is routed through the proxy", key)
			continue
		}
		for _, must := range []string{"localhost", ".svc"} {
			if !strings.Contains(env[key], must) {
				t.Errorf("%s = %q does not exempt %q", key, env[key], must)
			}
		}
	}
	if env["NO_PROXY"] != env["no_proxy"] {
		t.Errorf("NO_PROXY (%q) and no_proxy (%q) disagree", env["NO_PROXY"], env["no_proxy"])
	}
}
