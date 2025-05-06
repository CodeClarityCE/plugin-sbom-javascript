package resolver

import (
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
	semver "github.com/CodeClarityCE/utility-node-semver"
)

func ResolvePNPMV9(lockFile schemas.PNPMLockFileV9) (types.LockFileInformation, error) {
	LockFileInformation := types.LockFileInformation{
		Dependencies:    map[string]map[string]types.Versions{},
		PackageManager:  packageManager.PNPM,
		LockFileVersion: 9,
	}

	for dependency_name, dependency := range lockFile.Snapshots {
		if dependency_name == "" {
			continue
		}
		dependency_name = strings.Replace(dependency_name, "node_modules/", "", 1)
		dependency_name_version := strings.Split(dependency_name, "(")[0]
		dependency_name_version_splitted := strings.Split(dependency_name_version, "@")
		dependency_version := dependency_name_version_splitted[len(dependency_name_version_splitted)-1]
		dependency_name = strings.Replace(dependency_name_version, "@"+dependency_version, "", -1)
		resolvedFilePackage := types.Versions{
			Requires:     dependency.Dependencies,
			Dependencies: make(map[string]string),
			Optional:     false,
			Bundled:      false,
			Dev:          false,
			Scoped:       false,
		}

		if dep, dependency_already_present := LockFileInformation.Dependencies[dependency_name]; dependency_already_present {
			if _, versiondependency_already_present := dep[dependency_version]; !versiondependency_already_present {
				LockFileInformation.Dependencies[dependency_name][dependency_version] = resolvedFilePackage
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
