package resolver

import (
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
	semver "github.com/CodeClarityCE/utility-node-semver"
)

func ResolveNPMV2(lockFile schemas.NPMLockFileV2) (types.LockFileInformation, error) {
	LockFileInformation := types.LockFileInformation{
		Dependencies:    map[string]map[string]types.Versions{},
		PackageManager:  packageManager.NPM,
		LockFileVersion: 2,
	}

	for dependency_name, dependency := range lockFile.Packages {
		if dependency_name == "" {
			continue
		}
		dependency_name = strings.Replace(dependency_name, "node_modules/", "", 1)
		resolvedFilePackage := types.Versions{
			Requires:     dependency.Dependencies,
			Dependencies: make(map[string]string),
			Optional:     dependency.Optional,
			Bundled:      dependency.InBundle,
			Dev:          dependency.Dev,
			Scoped:       false,
		}
		if dep, dependency_already_present := LockFileInformation.Dependencies[dependency_name]; dependency_already_present {
			if _, versiondependency_already_present := dep[dependency.Version]; !versiondependency_already_present {
				LockFileInformation.Dependencies[dependency_name][dependency.Version] = resolvedFilePackage
			}
		} else {
			LockFileInformation.Dependencies[dependency_name] = map[string]types.Versions{
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
