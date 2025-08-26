package js

import (
	"log"
	"os"
	"path/filepath"

	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/utility-types/boilerplates"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/google/uuid"
)

// JSSBOMAnalyzer implements the SBOMAnalyzer interface for JavaScript projects
type JSSBOMAnalyzer struct{}

// AnalyzeProject performs JavaScript SBOM analysis
func (j *JSSBOMAnalyzer) AnalyzeProject(projectPath string, analysisId string, knowledgeDB any) (boilerplates.SBOMOutput, error) {
	log.Printf("JavaScript SBOM Analysis - Starting analysis for project: %s", projectPath)

	// Convert analysisId string back to UUID for compatibility with existing Start function
	analysisUUID, err := uuid.Parse(analysisId)
	if err != nil {
		log.Printf("Failed to parse analysis ID: %v", err)
		analysisUUID = uuid.New() // Generate new UUID if parsing fails
	}

	// Call the existing JavaScript SBOM Start function from run.go
	output := Start(projectPath, analysisUUID)

	// Wrap the output to implement our SBOMOutput interface
	return &JSSBOMOutput{Output: output}, nil
}

// CanAnalyze checks if this analyzer can handle the given project
func (j *JSSBOMAnalyzer) CanAnalyze(projectPath string) bool {
	// Check for JavaScript/Node.js project files
	packageJson := filepath.Join(projectPath, "package.json")

	// Check for package.json (required)
	if _, err := os.Stat(packageJson); err == nil {
		log.Printf("JavaScript SBOM - Found package.json at: %s", packageJson)
		return true
	}

	// Also check for lock files even without package.json (edge case)
	lockFiles := []string{
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
	}

	for _, lockFile := range lockFiles {
		lockPath := filepath.Join(projectPath, lockFile)
		if _, err := os.Stat(lockPath); err == nil {
			log.Printf("JavaScript SBOM - Found %s at: %s", lockFile, lockPath)
			return true
		}
	}

	log.Printf("JavaScript SBOM - No JavaScript project files found in: %s", projectPath)
	return false
}

// GetLanguage returns the language this analyzer handles
func (j *JSSBOMAnalyzer) GetLanguage() string {
	return "JavaScript"
}

// DetectFramework detects the JavaScript framework used in the project
func (j *JSSBOMAnalyzer) DetectFramework(projectPath string) string {
	// Framework detection is handled during the analysis process
	// We'll return empty here and let the analysis populate it
	return ""
}

// ConvertToMap converts the JavaScript SBOM output to map[string]any for storage
func (j *JSSBOMAnalyzer) ConvertToMap(output boilerplates.SBOMOutput) map[string]any {
	if jsOutput, ok := output.(*JSSBOMOutput); ok {
		// Use the existing ConvertSbomToMap function
		result := sbom.ConvertSbomToMap(jsOutput.Output)

		// Convert map[string]interface{} to map[string]any
		converted := make(map[string]any)
		for k, v := range result {
			converted[k] = v
		}
		return converted
	}
	return map[string]any{}
}

// GetDependencyCount returns the total number of dependencies found
func (j *JSSBOMAnalyzer) GetDependencyCount(output boilerplates.SBOMOutput) int {
	if jsOutput, ok := output.(*JSSBOMOutput); ok {
		total := 0
		for _, workspace := range jsOutput.Output.WorkSpaces {
			total += len(workspace.Dependencies)
		}
		return total
	}
	return 0
}

// JSSBOMOutput wraps the existing JavaScript sbom.Output to implement SBOMOutput interface
type JSSBOMOutput struct {
	Output sbom.Output
}

// GetStatus returns the analysis status
func (j *JSSBOMOutput) GetStatus() codeclarity.AnalysisStatus {
	return j.Output.AnalysisInfo.Status
}

// GetFramework returns the detected framework
func (j *JSSBOMOutput) GetFramework() string {
	// JavaScript SBOM doesn't have explicit framework field in Extra
	// We can detect based on dependencies or return empty
	return ""
}
