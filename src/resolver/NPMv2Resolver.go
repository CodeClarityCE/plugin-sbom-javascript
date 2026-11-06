package resolver

import (
	"sort"
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
)

func ResolveNPMV2(lockFile schemas.NPMLockFileV2) (types.LockFileInformation, error) {
	LockFileInformation := types.LockFileInformation{
		Dependencies:    map[string]map[string]types.Versions{},
		PackageManager:  packageManager.NPM,
		LockFileVersion: 2,
	}

	// Sort paths so the same lockfile always gives the same result.
	paths := make([]string, 0, len(lockFile.Packages))
	for path := range lockFile.Packages {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	installPath := map[string]map[string]string{}

	for _, dependency_name := range paths {
		dependency := lockFile.Packages[dependency_name]
		if dependency_name == "" {
			continue
		}
		path := dependency_name
		splitted_dependency_name := strings.Split(dependency_name, "node_modules/")
		dependency_name = splitted_dependency_name[len(splitted_dependency_name)-1]
		resolvedFilePackage := types.Versions{
			Requires:     dependency.Dependencies,
			Dependencies: make(map[string]string),
			Optional:     dependency.Optional,
			Bundled:      dependency.InBundle,
			Dev:          dependency.Dev,
			Scoped:       false,
		}
		if installPath[dependency_name] == nil {
			installPath[dependency_name] = map[string]string{}
		}
		if _, seen := installPath[dependency_name][dependency.Version]; !seen {
			installPath[dependency_name][dependency.Version] = path
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

	for name, dependency := range LockFileInformation.Dependencies {
		for versionKey, version := range dependency {
			from := installPath[name][versionKey]
			for requiredName, requiredConstraint := range version.Requires {
				requiredDependency, present := LockFileInformation.Dependencies[requiredName]
				if !present {
					continue
				}
				if installed, ok := lockFile.Packages[npmInstallLookup(lockFile.Packages, from, requiredName)]; ok {
					if _, inLockfile := requiredDependency[installed.Version]; inLockfile {
						version.Dependencies[requiredName] = installed.Version
						continue
					}
				}
				constraint := strings.Replace(requiredConstraint, "npm:", "", 1)
				if best, ok := highestSatisfying(requiredDependency, constraint); ok {
					version.Dependencies[requiredName] = best
				}
			}
		}
	}

	return LockFileInformation, nil
}

// npmInstallLookup returns the path Node would load requiredName from,
// starting at from and walking up. It returns "" if there is none.
func npmInstallLookup[T any](packages map[string]T, from, requiredName string) string {
	dir := from
	for {
		candidate := "node_modules/" + requiredName
		if dir != "" {
			candidate = dir + "/" + candidate
		}
		if _, ok := packages[candidate]; ok {
			return candidate
		}
		if dir == "" {
			return ""
		}
		// Go up one node_modules level.
		idx := strings.LastIndex(dir, "node_modules/")
		if idx <= 0 {
			dir = ""
		} else {
			dir = strings.TrimSuffix(dir[:idx], "/")
		}
	}
}
