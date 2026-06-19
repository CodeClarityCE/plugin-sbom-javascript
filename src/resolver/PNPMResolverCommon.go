package resolver

import (
	"log"
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	semver "github.com/CodeClarityCE/utility-node-semver"
)

// resolvePNPMTransitives fills each version's Dependencies map by semver-matching
// its Requires constraints against the versions actually present in the lockfile.
// Shared by every pnpm format family (v5, v6, v9) since the resolution step is
// identical once the flat name->version->Versions graph has been built.
func resolvePNPMTransitives(LockFileInformation types.LockFileInformation) {
	for _, dependency := range LockFileInformation.Dependencies {
		for _, version := range dependency {
			for requiredName, requiredConstraint := range version.Requires {
				requiredConstraint = strings.Replace(requiredConstraint, "npm:", "", 1)
				// If the version required is latest, we replace by a wildcard
				if requiredConstraint == "latest" {
					requiredConstraint = "*"
				}
				requiredConstraintSemver, err := semver.ParseConstraint(requiredConstraint)
				if err != nil {
					log.Println("Cannot parse constraint ", requiredConstraint)
					requiredConstraintSemver, _ = semver.ParseConstraint("*")
				}
				if requiredDependency, dependencyAlreadyPresent := LockFileInformation.Dependencies[requiredName]; dependencyAlreadyPresent {
					for requiredVersion := range requiredDependency {
						requiredVersionSemver, err := semver.ParseSemver(requiredVersion)
						if err != nil {
							log.Println("Cannot parse semver ", requiredVersion)
							continue
						}
						if semver.Satisfies(requiredVersionSemver, requiredConstraintSemver, false) {
							version.Dependencies[requiredName] = requiredVersion
						}
					}
				}
			}
		}
	}
}
