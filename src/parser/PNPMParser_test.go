package parser

import (
	"os"
	"testing"
)

// These tests exercise the pnpm parsers directly (without run.go, which requires
// RabbitMQ) against the real v5/v6 lockfile fixtures, asserting the ticket's
// acceptance criterion: older lockfiles resolve a non-empty dependency tree.

func TestParsePNPMV5Fixture(t *testing.T) {
	data, err := os.ReadFile("../../tests/pnpmv5/pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	info, err := parsePNPM(data)
	if err != nil {
		t.Fatalf("parsePNPM (v5) returned error: %v", err)
	}
	if info.LockFileVersion != 5 {
		t.Errorf("LockFileVersion = %d; want 5", info.LockFileVersion)
	}
	if len(info.Dependencies) == 0 {
		t.Fatal("v5 dependency tree is empty")
	}
	chalk, ok := info.Dependencies["chalk"]["1.1.3"]
	if !ok {
		t.Fatal("expected chalk@1.1.3 in v5 tree")
	}
	// chalk@1.1.3 depends on ansi-styles 2.2.1 — verifies transitive resolution.
	if got := chalk.Dependencies["ansi-styles"]; got != "2.2.1" {
		t.Errorf("chalk transitive ansi-styles = %q; want 2.2.1", got)
	}
}

func TestParsePNPMV6Fixture(t *testing.T) {
	data, err := os.ReadFile("../../tests/pnpmv6/pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	info, err := parsePNPM(data)
	if err != nil {
		t.Fatalf("parsePNPM (v6) returned error: %v", err)
	}
	if info.LockFileVersion != 6 {
		t.Errorf("LockFileVersion = %d; want 6", info.LockFileVersion)
	}
	if len(info.Dependencies) == 0 {
		t.Fatal("v6 dependency tree is empty")
	}
	// Key `/ajv-keywords@3.4.1(ajv@6.10.2)` must clean to name/version without the peer suffix.
	ajvKeywords, ok := info.Dependencies["ajv-keywords"]["3.4.1"]
	if !ok {
		t.Fatal("expected ajv-keywords@3.4.1 in v6 tree (peer suffix not stripped from key?)")
	}
	// ajv-keywords requires ajv; the `_peer`-free version must resolve to 6.10.2.
	if got := ajvKeywords.Dependencies["ajv"]; got != "6.10.2" {
		t.Errorf("ajv-keywords transitive ajv = %q; want 6.10.2", got)
	}
}
