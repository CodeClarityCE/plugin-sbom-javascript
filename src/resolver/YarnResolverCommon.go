package resolver

import (
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
)

// yarnSpecifiers maps each "name@range" in an entry's key to its version.
// A key can list several ranges, e.g. "a@npm:^1.0.0, a@npm:^1.2.0".
func yarnSpecifiers(entryKey string, version string, specifiers map[string]string) {
	for _, specifier := range strings.Split(entryKey, ",") {
		specifier = strings.Trim(strings.TrimSpace(specifier), `"`)
		if specifier == "" {
			continue
		}
		specifiers[normaliseYarnSpecifier(specifier)] = version
	}
}

func normaliseYarnSpecifier(specifier string) string {
	// The separator is the last "@" that is not the scope marker at index 0.
	at := strings.LastIndex(specifier, "@")
	if at <= 0 {
		return specifier
	}
	return specifier[:at] + "@" + strings.Replace(specifier[at+1:], "npm:", "", 1)
}

// resolveYarnTransitives links each package to the versions it depends on,
// using the version the lockfile recorded for each range.
func resolveYarnTransitives(lockFileInformation types.LockFileInformation, specifiers map[string]string) {
	for _, dependency := range lockFileInformation.Dependencies {
		for _, version := range dependency {
			for requiredName, requiredConstraint := range version.Requires {
				requiredConstraint = strings.Replace(requiredConstraint, "npm:", "", 1)
				requiredDependency, present := lockFileInformation.Dependencies[requiredName]
				if !present {
					continue
				}
				if resolved, ok := specifiers[requiredName+"@"+requiredConstraint]; ok {
					if _, inLockfile := requiredDependency[resolved]; inLockfile {
						version.Dependencies[requiredName] = resolved
						continue
					}
				}
				if best, ok := highestSatisfying(requiredDependency, requiredConstraint); ok {
					version.Dependencies[requiredName] = best
				}
			}
		}
	}
}
