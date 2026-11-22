package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
)

// Run `go test ./tests/ -update` to rewrite the fixture sbom.json files.
var update = flag.Bool("update", false, "rewrite the fixture sbom.json files")

// writeJSON writes under the source tests folder, not the test's tempdir.
func writeJSON(data any, path string) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil || !*update {
		return err
	}
	return os.WriteFile(filepath.Join(sourceDir, path), jsonData, 0644)
}
