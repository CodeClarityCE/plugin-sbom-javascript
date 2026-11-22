package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// Run `go test ./tests/ -update` to rewrite the fixture sbom.json files.
var update = flag.Bool("update", false, "rewrite the fixture sbom.json files")

// writeJSON writes under the source tests folder, not the test's tempdir.
func writeJSON(t *testing.T, data any, path string) {
	t.Helper()
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !*update {
		return
	}
	if err := os.WriteFile(filepath.Join(sourceDir, path), jsonData, 0o600); err != nil {
		t.Fatal(err)
	}
}
