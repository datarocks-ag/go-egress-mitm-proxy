// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package trace

import (
	"bytes"
	"log/slog"
	"testing"

	"go-egress-proxy/internal/config"
)

// recordFor builds a Record whose rule has the given body-capture setting.
func recordFor(t *testing.T, buf *bytes.Buffer, bodies config.BodyCaptureConfig) *Record {
	t.Helper()

	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled: true,
		Rules:   []config.TraceRule{{Host: "*", Bodies: bodies}},
	})
	if err != nil {
		t.Fatalf("CompileTrace: %v", err)
	}
	return NewRecord("tid", "mitm", &ct.Rules[0], NewRedactor(ct), StaticLogger(slog.New(slog.NewJSONHandler(buf, nil))))
}
