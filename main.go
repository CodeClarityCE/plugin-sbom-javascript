package main

import (
	"log"

	js "github.com/CodeClarityCE/plugin-sbom-javascript/src"
	"github.com/CodeClarityCE/utility-boilerplates"
)

// main is the entry point for the JavaScript SBOM plugin
func main() {
	// Create the JavaScript SBOM analyzer
	analyzer := &js.JSSBOMAnalyzer{}

	// Create and start the plugin using the generic SBOM plugin base
	err := boilerplates.CreateSBOMPlugin(analyzer)
	if err != nil {
		log.Fatalf("JavaScript SBOM Plugin failed: %v", err)
	}
}
