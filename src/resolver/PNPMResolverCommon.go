package resolver

import (
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
)

// resolvePNPMTransitives links each package to the versions it depends on.
// Used by all pnpm lockfile versions.
func resolvePNPMTransitives(LockFileInformation types.LockFileInformation) {
	fillDependencies(LockFileInformation.Dependencies, nil)
}
