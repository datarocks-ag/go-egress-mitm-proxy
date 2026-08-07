// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log/slog"
	"os"

	"go-egress-proxy/internal/cert"
	"go-egress-proxy/internal/config"
	"go-egress-proxy/internal/metrics"
)

// connectionPool is the part of proxy.TransportPool that reload needs. Narrowing
// it to one method lets tests observe that the pool was reset without standing
// up real transports.
type connectionPool interface {
	Reset()
}

// logOpener opens a log file, returning its logger and handle. Matches
// config.OpenBlockedLog and config.OpenTraceLog.
type logOpener func(path string) (*slog.Logger, *os.File, error)

// reloadDeps is what a config reload operates on.
type reloadDeps struct {
	configPath string
	runtimeCfg *config.RuntimeConfig
	pool       connectionPool

	// openBlockedLog and openTraceLog default to the config package functions.
	// They exist so a test can observe that a reload aborting between the two
	// closes the first handle. Asserting that indirectly does not work: os.File
	// finalizers close leaked descriptors during GC, so a leak never manifests
	// as exhaustion and an rlimit-based test passes with the cleanup removed.
	openBlockedLog logOpener
	openTraceLog   logOpener
}

func (d reloadDeps) blockedOpener() logOpener {
	if d.openBlockedLog != nil {
		return d.openBlockedLog
	}
	return config.OpenBlockedLog
}

func (d reloadDeps) traceOpener() logOpener {
	if d.openTraceLog != nil {
		return d.openTraceLog
	}
	return config.OpenTraceLog
}

// reload re-reads the config file and swaps in the new configuration.
//
// It is all-or-nothing. Every failure returns before RuntimeConfig is touched,
// so the running configuration survives a bad edit -- the property that makes
// SIGHUP safe to use on a live proxy, and the one most worth testing. Any log
// files opened before the failing step are closed on the way out, or a repeated
// failing reload would leak a file descriptor per attempt.
//
// This lives outside main() so the whole path is reachable from tests: it was
// previously an inline block in a goroutine inside main, which is why none of
// the retain-previous-config behavior, the fd-cleanup branches, or the
// pool reset had any coverage.
func reload(deps reloadDeps) error {
	newCfg, newACL, newRewrites, err := config.LoadAndCompileConfig(deps.configPath)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	newTrace, err := config.CompileTrace(newCfg.Trace)
	if err != nil {
		return fmt.Errorf("compile trace configuration: %w", err)
	}

	newBlockedLogger, newBlockedFile, err := deps.blockedOpener()(newCfg.Proxy.BlockedLogPath)
	if err != nil {
		return fmt.Errorf("open blocked log %q: %w", newCfg.Proxy.BlockedLogPath, err)
	}

	newTraceLogger, newTraceFile, err := deps.traceOpener()(newCfg.Trace.LogPath)
	if err != nil {
		closeFile(newBlockedFile, "blocked log")
		return fmt.Errorf("open trace log %q: %w", newCfg.Trace.LogPath, err)
	}

	newTLSConfig, err := cert.BuildOutboundTLSConfig(newCfg)
	if err != nil {
		closeFile(newBlockedFile, "blocked log")
		closeFile(newTraceFile, "trace log")
		return fmt.Errorf("build outbound TLS configuration: %w", err)
	}

	// Warn about settings that changed but cannot be applied without a restart,
	// rather than reporting a clean reload that silently ignored them.
	previousCfg, _, _, _, _ := deps.runtimeCfg.Get()
	if ignored := config.ReloadIgnoredFields(previousCfg, newCfg); len(ignored) > 0 {
		slog.Warn("Configuration changes require a restart and were NOT applied",
			"fields", ignored,
			"hint", "certificate and listen-port changes take effect on restart only")
	}

	// Past this point the reload commits: everything that can fail has.
	closeFile(deps.runtimeCfg.Update(newCfg, newACL, newRewrites, newTLSConfig, newBlockedLogger, newBlockedFile),
		"rotated blocked log")
	closeFile(deps.runtimeCfg.SetTrace(newTrace, newTraceLogger, newTraceFile), "rotated trace log")

	// Rewrite targets may now resolve elsewhere; drop pooled connections to the
	// previous targets instead of letting them serve until IdleConnTimeout.
	if deps.pool != nil {
		deps.pool.Reset()
	}

	slog.Info("Configuration reloaded successfully",
		"rewrites", len(newRewrites),
		"whitelist", len(newACL.Whitelist),
		"blacklist", len(newACL.Blacklist),
		"passthrough", len(newACL.Passthrough))
	return nil
}

// closeFile closes f when non-nil, warning rather than failing: by the time it
// is called the reload has either already failed for another reason, or already
// committed.
func closeFile(f *os.File, what string) {
	if f == nil {
		return
	}
	if err := f.Close(); err != nil {
		slog.Warn("Failed to close file", "what", what, "err", err)
	}
}

// watchSIGHUP reloads on every signal received on ch, recording the outcome in
// the config metrics.
func watchSIGHUP(ch <-chan os.Signal, deps reloadDeps) {
	for range ch {
		slog.Info("SIGHUP received, reloading configuration...")
		if err := reload(deps); err != nil {
			slog.Error("Failed to reload configuration; keeping previous configuration", "err", err)
			metrics.ConfigLoadErrors.Inc()
			continue
		}
		metrics.ConfigReloads.Inc()
	}
}
