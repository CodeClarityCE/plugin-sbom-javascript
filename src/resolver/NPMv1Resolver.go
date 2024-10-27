package resolver

import (
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
	semver "github.com/CodeClarityCE/utility-node-semver"
)

func ResolveNPMV1(lockFile schemas.NPMLockFileV1) (types.LockFileInformation, error) {
	LockFileInformation := types.LockFileInformation{
		PackageManager:  packageManager.NPM,
		LockFileVersion: 1,
		Dependencies:    make(map[string]map[string]types.Versions),
	}
	flattenedDependencies := make(map[string]schemas.NPMLockFileV1Dependency)

	flattenNPMV1LockFile(lockFile.Dependencies, flattenedDependencies, "")

	for _, dependency := range flattenedDependencies {
		resolvedFilePackage := types.Versions{
			Requires:     dependency.Requires,
			Dependencies: make(map[string]string),
			Optional:     dependency.Optional,
			Bundled:      false,
			Dev:          false,
			Scoped:       false,
		}
		if dep, dependency_already_present := LockFileInformation.Dependencies[dependency.Name]; dependency_already_present {
			if _, versiondependency_already_present := dep[dependency.Version]; !versiondependency_already_present {
				LockFileInformation.Dependencies[dependency.Name][dependency.Version] = resolvedFilePackage
			}
		} else {
			LockFileInformation.Dependencies[dependency.Name] = map[string]types.Versions{
				dependency.Version: resolvedFilePackage,
			}
		}
	}

	for _, dependency := range LockFileInformation.Dependencies {
		for _, version := range dependency {
			for requiredName, requiredConstraint := range version.Requires {
				requiredConstraintSemver, err := semver.ParseConstraint(requiredConstraint)
				if err != nil {
					continue
				}
				if requiredDependency, dependencyAlreadyPresent := LockFileInformation.Dependencies[requiredName]; dependencyAlreadyPresent {
					for requiredVersion := range requiredDependency {
						requiredVersionSemver, err := semver.ParseSemver(requiredVersion)
						if err != nil {
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

	return LockFileInformation, nil
}

func flattenNPMV1LockFile(dependencies map[string]schemas.NPMLockFileV1Dependency, flattenedDependencies map[string]schemas.NPMLockFileV1Dependency, path string) {
	for name, dep := range dependencies {
		dep.Name = name

		key := path + "|" + name
		key = strings.TrimPrefix(key, "|")

		flattenedDependencies[key] = dep
		if dep.Dependencies != nil {
			flattenNPMV1LockFile(dep.Dependencies, flattenedDependencies, key)
		}
	}
}
