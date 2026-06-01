// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Live drift report formatter for the validate --live subcommand (Fix 2).
//
// runValidateLive classifies every live tool against the manifest and renders
// four sections:
//
//	COVERED              — tools matched by exact manifest entries (unambiguous)
//	WARNINGS             — FM-1 glob-matched tools + FM-3 argument drift (review required)
//	NOT COVERED          — tools with no manifest entry (denied by default)
//	STALE MANIFEST ENTRIES — manifest entries with no live tool match (FM-2)
//
// Exit code 0 means the manifest is clean: every entry matches a live tool and
// no live tool is matched only via a glob.  Exit code 1 means FM-1 or FM-2
// findings are present and operator review is required.

package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// coveredEntry records a live tool that is covered by an exact manifest entry.
type coveredEntry struct {
	Tool     string
	Resource string
}

// liveReport holds the classified findings from a live drift check.
type liveReport struct {
	exactCovered []coveredEntry // tools covered by exact-match entries
	fm1Warnings  []DriftWarning // FM-1: glob-matched tools
	fm3Warnings  []DriftWarning // FM-3: condition argument not in live schema
	fm4Warnings  []DriftWarning // FM-4: server version does not satisfy manifest pin
	fm2Stale     []DriftWarning // FM-2: manifest entries with no live tool
	uncovered    []string       // live tool names not covered by any manifest entry
}

// buildLiveReport classifies the live tool set against the manifest using
// CheckManifestDrift and returns a liveReport ready for rendering.
// serverVersion is the version string from the upstream initialize response.
func buildLiveReport(manifest *LocalManifest, tools []UpstreamTool, serverVersion string) liveReport {
	driftWarnings := CheckManifestDrift(manifest, tools, serverVersion)

	fm1 := make(map[string]DriftWarning)
	fm2 := make(map[string]DriftWarning)
	var fm3, fm4 []DriftWarning
	uncoveredSet := make(map[string]bool)

	for _, w := range driftWarnings {
		switch w.Kind {
		case DriftFM1:
			fm1[w.Tool] = w
		case DriftFM2:
			fm2[w.Resource] = w
		case DriftFM3:
			fm3 = append(fm3, w)
		case DriftFM4:
			fm4 = append(fm4, w)
		case DriftUncovered:
			uncoveredSet[w.Tool] = true
		}
	}

	// Exact-covered: live tools that are NOT glob-matched (FM-1) and NOT uncovered.
	var exactCovered []coveredEntry
	for _, tool := range tools {
		if uncoveredSet[tool.Name] {
			continue
		}
		if _, isFM1 := fm1[tool.Name]; isFM1 {
			continue
		}
		if c := bestManifestConstraint(manifest, tool.Name); c != nil {
			exactCovered = append(exactCovered, coveredEntry{Tool: tool.Name, Resource: c.Resource})
		}
	}
	sort.Slice(exactCovered, func(i, j int) bool {
		return exactCovered[i].Tool < exactCovered[j].Tool
	})

	fm1Slice := make([]DriftWarning, 0, len(fm1))
	for _, w := range fm1 {
		fm1Slice = append(fm1Slice, w)
	}
	sort.Slice(fm1Slice, func(i, j int) bool {
		return fm1Slice[i].Tool < fm1Slice[j].Tool
	})

	fm2Slice := make([]DriftWarning, 0, len(fm2))
	for _, w := range fm2 {
		fm2Slice = append(fm2Slice, w)
	}
	sort.Slice(fm2Slice, func(i, j int) bool {
		return fm2Slice[i].Resource < fm2Slice[j].Resource
	})

	uncoveredSlice := make([]string, 0, len(uncoveredSet))
	for name := range uncoveredSet {
		uncoveredSlice = append(uncoveredSlice, name)
	}
	sort.Strings(uncoveredSlice)

	return liveReport{
		exactCovered: exactCovered,
		fm1Warnings:  fm1Slice,
		fm3Warnings:  fm3,
		fm4Warnings:  fm4,
		fm2Stale:     fm2Slice,
		uncovered:    uncoveredSlice,
	}
}

// runValidateLive writes a human-readable drift report to out and returns the
// appropriate exit code.
//
// Returns 0 when the manifest is clean (no FM-1, no FM-2, no FM-4).
// Returns 1 when warnings or stale entries are present.
func runValidateLive(manifest *LocalManifest, tools []UpstreamTool, serverVersion string, out io.Writer) int {
	rep := buildLiveReport(manifest, tools, serverVersion)

	// wf and wln are write helpers: errors on terminal output are not actionable
	// by the caller, so they are intentionally discarded.
	wf := func(format string, args ...interface{}) { _, _ = fmt.Fprintf(out, format, args...) }
	wln := func(args ...interface{}) { _, _ = fmt.Fprintln(out, args...) }

	// gap emits a blank line between sections, but not before the first one.
	printed := false
	gap := func() {
		if printed {
			wln()
		}
		printed = true
	}

	if len(rep.exactCovered) > 0 {
		gap()
		wln("COVERED")
		for _, e := range rep.exactCovered {
			wf("  ✓ %-22s resource: %s\n", e.Tool, e.Resource)
		}
	}

	if len(rep.fm4Warnings) > 0 || len(rep.fm1Warnings) > 0 || len(rep.fm3Warnings) > 0 {
		gap()
		wln("WARNINGS")
		for _, w := range rep.fm4Warnings {
			actual := w.VersionActual
			if actual == "" {
				actual = "(unknown)"
			}
			wf("  ⚠ SERVER VERSION MISMATCH  pinned: %-18s actual: %s\n", w.Resource, actual)
		}
		for _, w := range rep.fm1Warnings {
			wf("  ⚠ %-22s resource: %-22s (glob match — confirm this is intended)\n", w.Tool, w.Resource)
		}
		for _, w := range rep.fm3Warnings {
			wf("  ⚠ %-22s argument=%q not in live inputSchema  (resource: %s)\n", w.Tool, w.Argument, w.Resource)
		}
	}

	if len(rep.uncovered) > 0 {
		gap()
		wln("NOT COVERED (denied by default)")
		for _, name := range rep.uncovered {
			wf("  - %s\n", name)
		}
	}

	if len(rep.fm2Stale) > 0 {
		gap()
		wln("STALE MANIFEST ENTRIES")
		for _, w := range rep.fm2Stale {
			wf("  ✗ %s  — no matching upstream tool\n", w.Resource)
		}
	}

	gap()

	fm1Count := len(rep.fm1Warnings)
	fm2Count := len(rep.fm2Stale)
	fm4Count := len(rep.fm4Warnings)

	if fm1Count == 0 && fm2Count == 0 && fm4Count == 0 {
		wln("Result: ok — all manifest entries match live tools; no glob matches detected.")
		return 0
	}

	var parts []string
	if fm4Count > 0 {
		parts = append(parts, "server version mismatch")
	}
	if fm1Count == 1 {
		parts = append(parts, "1 glob match")
	} else if fm1Count > 1 {
		parts = append(parts, fmt.Sprintf("%d glob matches", fm1Count))
	}
	if fm2Count == 1 {
		parts = append(parts, "1 stale entry")
	} else if fm2Count > 1 {
		parts = append(parts, fmt.Sprintf("%d stale entries", fm2Count))
	}
	wf("Result: %s. Exit 1.\n", strings.Join(parts, ", "))
	return 1
}
