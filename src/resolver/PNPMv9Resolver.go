package resolver

import (
	"sort"
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
)

func ResolvePNPMV9(lockFile schemas.PNPMLockFileV9) (types.LockFileInformation, error) {
	LockFileInformation := types.LockFileInformation{
		Dependencies:    map[string]map[string]types.Versions{},
		PackageManager:  packageManager.PNPM,
		LockFileVersion: 9,
	}

	// pnpm keeps one snapshot per peer variant, e.g. p@1.0.0(typescript@5.9.3).
	// They share one entry and the first one wins, so sort the keys.
	snapshotKeys := make([]string, 0, len(lockFile.Snapshots))
	for key := range lockFile.Snapshots {
		snapshotKeys = append(snapshotKeys, key)
	}
	sort.Strings(snapshotKeys)

	for _, dependency_name := range snapshotKeys {
		dependency := lockFile.Snapshots[dependency_name]
		if dependency_name == "" {
			continue
		}

		name, dependency_version := cleanName(dependency_name)

		// Drop the peer suffix: "8.3.6(typescript@5.6.3)" becomes "8.3.6".
		requires := make(map[string]string, len(dependency.Dependencies)+len(dependency.OptionalDependencies))
		for depName, depVersion := range dependency.Dependencies {
			requires[depName] = stripPeerSuffixV6(depVersion)
		}
		// Optional dependencies count as dependencies too.
		for depName, depVersion := range dependency.OptionalDependencies {
			requires[depName] = stripPeerSuffixV6(depVersion)
		}

		resolvedFilePackage := types.Versions{
			Requires:     requires,
			Dependencies: make(map[string]string),
			Optional:     dependency.Optional,
			Bundled:      false,
			Dev:          false,
			Scoped:       false,
		}

		if dep, dependency_already_present := LockFileInformation.Dependencies[name]; dependency_already_present {
			if _, versiondependency_already_present := dep[dependency_version]; !versiondependency_already_present {
				LockFileInformation.Dependencies[name][dependency_version] = resolvedFilePackage
			}
		} else {
			LockFileInformation.Dependencies[name] = map[string]types.Versions{
				dependency_version: resolvedFilePackage,
			}
		}
	}

	resolvePNPMTransitives(LockFileInformation)
	LockFileInformation.ResolveDirect = func(workspacePath, name, _ string) (string, string, bool) {
		importer := lockFile.Importers[workspacePath]
		for _, declared := range []map[string]schemas.PNPMLockFileV9ImporterDependency{importer.Dependencies, importer.DevDependencies, importer.OptionalDependencies} {
			entry, ok := declared[name]
			if !ok {
				continue
			}
			version := stripPeerSuffixV6(entry.Version)
			if realName, realVersion, isAlias := splitNpmAlias(version); isAlias {
				return realName, realVersion, true
			}
			return name, version, true
		}
		return "", "", false
	}

	return LockFileInformation, nil
}

func cleanName(key string) (string, string) {
	dependency_name := strings.Replace(key, "node_modules/", "", 1)
	dependency_name_version, _, _ := strings.Cut(dependency_name, "(")
	dependency_name_version_splitted := strings.Split(dependency_name_version, "@")
	dependency_version := dependency_name_version_splitted[len(dependency_name_version_splitted)-1]
	dependency_name = strings.Replace(dependency_name_version, "@"+dependency_version, "", -1)
	return dependency_name, dependency_version
}
