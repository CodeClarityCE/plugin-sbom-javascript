package workspace

import (
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
)

func isTransitive(dependencies map[string]map[string]types.Versions, testedDependencyName string, testedDependencyVersion string) bool {
	for _, dependency := range dependencies {
		for _, versionInfo := range dependency {
			if versionInfo.Dependencies[testedDependencyName] == testedDependencyVersion {
				return true
			}
		}
	}

	return false
}
