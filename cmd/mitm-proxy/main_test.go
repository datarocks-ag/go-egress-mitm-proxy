package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestVersionDefault(t *testing.T) {
	if version != "dev" {
		t.Errorf("version = %q, want %q", version, "dev")
	}
}

func TestPrintUsage(t *testing.T) {
	// Capture stderr output
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	printUsage()

	w.Close() //nolint:errcheck // flushing pipe before read
	os.Stderr = oldStderr

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	r.Close() //nolint:errcheck // best-effort cleanup after read
	output := buf.String()

	for _, want := range []string{"validate", "--version", "--help", "-v", "-vv", "-vvv", "CONFIG_PATH"} {
		if !strings.Contains(output, want) {
			t.Errorf("printUsage() output missing %q", want)
		}
	}
}
