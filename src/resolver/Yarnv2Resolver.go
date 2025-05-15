package resolver

import (
	"log"
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
	semver "github.com/CodeClarityCE/utility-node-semver"
)

// ResolveYarnDependencies resolves the dependencies in a Yarn lock file and returns a resolved lock file.
// It takes a lockFile parameter of type schemas.UnversionedYarnLockFile and returns a resolved lock file of type schemas.LockFileInformation.
// The resolved lock file contains information about the resolved dependencies, including their versions, names, and dependencies.
// The function iterates over the dependencies in the lock file, creates a resolved file package for each dependency, and adds it to the resolved lock file.
// It also resolves the dependencies between the packages and adds them to the corresponding resolved file packages.
// Finally, it sets the lock file version and package manager in the resolved lock file and returns it.
func ResolveYarnv2(lockFile schemas.YarnV2LockFile) (types.LockFileInformation, error) {
	lockFileInformation := types.LockFileInformation{
		Dependencies:    make(map[string]map[string]types.Versions),
		LockFileVersion: 1,
		PackageManager:  packageManager.YARN,
	}

	for dependency_id, dependency := range lockFile {
		resolvedFilePackage := types.Versions{
			Requires:     dependency.Dependencies,
			Dependencies: make(map[string]string),
			Optional:     false,
			Bundled:      false,
			Dev:          false,
			Scoped:       false,
		}

		dependency_name := dependency_id
		if strings.HasPrefix(dependency_id, "@") {
			dependency_name = "@" + strings.Split(dependency_id, "@")[1]
		} else {
			dependency_name = strings.Split(dependency_id, "@")[0]
		}

		if dep, dependency_already_present := lockFileInformation.Dependencies[dependency_name]; dependency_already_present {
			if _, versiondependency_already_present := dep[dependency.Version]; !versiondependency_already_present {
				lockFileInformation.Dependencies[dependency_name][dependency.Version] = resolvedFilePackage
			}
		} else {
			lockFileInformation.Dependencies[dependency_name] = map[string]types.Versions{
				dependency.Version: resolvedFilePackage,
			}
		}
	}

	for _, dependency := range lockFileInformation.Dependencies {
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
				if requiredDependency, dependencyAlreadyPresent := lockFileInformation.Dependencies[requiredName]; dependencyAlreadyPresent {
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

	return lockFileInformation, nil
}
