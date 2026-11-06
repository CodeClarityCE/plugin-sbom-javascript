package main

import (
	"encoding/json"
	"flag"
	"os"
)

// Run `go test ./tests/ -update` to rewrite the fixture sbom.json files.
// js-patching's tests read them.
var update = flag.Bool("update", false, "rewrite the fixture sbom.json files")

func writeJSON(data any, filepath string) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil || !*update {
		return err
	}
	return os.WriteFile(filepath, jsonData, 0644)
}
