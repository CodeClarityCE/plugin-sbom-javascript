package resolver

import (
	"sort"
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
)

func ResolveNPMV1(lockFile schemas.NPMLockFileV1) (types.LockFileInformation, error) {
	LockFileInformation := types.LockFileInformation{
		PackageManager:  packageManager.NPM,
		LockFileVersion: 1,
		Dependencies:    make(map[string]map[string]types.Versions),
	}
	flattenedDependencies := make(map[string]schemas.NPMLockFileV1Dependency)

	flattenNPMV1LockFile(lockFile.Dependencies, flattenedDependencies, "")

	// Sort paths so the same lockfile always gives the same result.
	paths := make([]string, 0, len(flattenedDependencies))
	for path := range flattenedDependencies {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	installPath := map[string]map[string]string{}

	for _, path := range paths {
		dependency := flattenedDependencies[path]
		if installPath[dependency.Name] == nil {
			installPath[dependency.Name] = map[string]string{}
		}
		if _, seen := installPath[dependency.Name][dependency.Version]; !seen {
			installPath[dependency.Name][dependency.Version] = path
		}
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

	for name, dependency := range LockFileInformation.Dependencies {
		for versionKey, version := range dependency {
			from := installPath[name][versionKey]
			for requiredName, requiredConstraint := range version.Requires {
				requiredDependency, present := LockFileInformation.Dependencies[requiredName]
				if !present {
					continue
				}
				if installed, ok := flattenedDependencies[npmV1NestedLookup(flattenedDependencies, from, requiredName)]; ok {
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

// npmV1NestedLookup finds the closest copy of requiredName above from.
// Keys look like "parent|child". It returns "" if there is none.
func npmV1NestedLookup(flattened map[string]schemas.NPMLockFileV1Dependency, from, requiredName string) string {
	dir := from
	for {
		candidate := requiredName
		if dir != "" {
			candidate = dir + "|" + requiredName
		}
		if _, ok := flattened[candidate]; ok {
			return candidate
		}
		if dir == "" {
			return ""
		}
		if idx := strings.LastIndex(dir, "|"); idx < 0 {
			dir = ""
		} else {
			dir = dir[:idx]
		}
	}
}
