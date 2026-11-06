package resolver

import (
	"log"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	semver "github.com/CodeClarityCE/utility-node-semver"
)

// highestSatisfying returns the highest version that matches the constraint.
// It is used when the lockfile does not say which version was installed.
func highestSatisfying(versions map[string]types.Versions, constraint string) (string, bool) {
	// If the version required is latest, we replace by a wildcard
	if constraint == "latest" {
		constraint = "*"
	}
	parsedConstraint, err := semver.ParseConstraint(constraint)
	if err != nil {
		log.Println("Cannot parse constraint ", constraint)
		parsedConstraint, _ = semver.ParseConstraint("*")
	}
	var satisfying []string
	for candidate := range versions {
		candidateSemver, err := semver.ParseSemver(candidate)
		if err != nil {
			log.Println("Cannot parse semver ", candidate)
			continue
		}
		if semver.Satisfies(candidateSemver, parsedConstraint, false) {
			satisfying = append(satisfying, candidate)
		}
	}
	if len(satisfying) == 0 {
		return "", false
	}
	// -1 sorts from highest to lowest.
	sorted, err := semver.SortStrings(-1, satisfying)
	if err != nil {
		return "", false
	}
	return sorted[0], true
}
