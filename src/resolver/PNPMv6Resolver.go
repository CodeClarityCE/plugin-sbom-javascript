package resolver

import (
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
)

// ResolvePNPMV6 builds the flat dependency graph for a 6.x-family pnpm lockfile.
// Like v5 the resolved graph lives inside each `packages` entry, but the key
// format is `/name@version(peer@x.y.z)` (see cleanNameV6) and per-package
// dependency values carry a `(peer)` suffix (see stripPeerSuffixV6).
func ResolvePNPMV6(lockFile schemas.PNPMLockFileV6) (types.LockFileInformation, error) {
	LockFileInformation := types.LockFileInformation{
		Dependencies:    map[string]map[string]types.Versions{},
		PackageManager:  packageManager.PNPM,
		LockFileVersion: 6,
	}

	for key, pkg := range lockFile.Packages {
		if key == "" {
			continue
		}

		name, version := cleanNameV6(key)
		if name == "" || version == "" {
			continue
		}

		requires := make(map[string]string)
		for depName, depVersion := range pkg.Dependencies {
			requires[depName] = stripPeerSuffixV6(depVersion)
		}
		for depName, depVersion := range pkg.OptionalDependencies {
			requires[depName] = stripPeerSuffixV6(depVersion)
		}

		resolvedFilePackage := types.Versions{
			Requires:     requires,
			Dependencies: make(map[string]string),
			Optional:     pkg.Optional,
			Bundled:      false,
			Dev:          pkg.Dev,
			Scoped:       strings.HasPrefix(name, "@"),
		}

		if dep, dependency_already_present := LockFileInformation.Dependencies[name]; dependency_already_present {
			if _, versiondependency_already_present := dep[version]; !versiondependency_already_present {
				LockFileInformation.Dependencies[name][version] = resolvedFilePackage
			}
		} else {
			LockFileInformation.Dependencies[name] = map[string]types.Versions{
				version: resolvedFilePackage,
			}
		}
	}

	resolvePNPMTransitives(LockFileInformation)

	return LockFileInformation, nil
}

// cleanNameV6 extracts the package name and version from a 6.x-family package key
// of the form `/name@version(peer@x.y.z)`. After stripping the leading slash the
// format matches v9 keys, so the v9 cleanName logic is reused.
func cleanNameV6(key string) (string, string) {
	return cleanName(strings.TrimPrefix(key, "/"))
}

// stripPeerSuffixV6 drops the `(peer@x.y.z)` peer-resolution suffix that 6.x
// lockfiles append to versions, leaving the bare version.
func stripPeerSuffixV6(version string) string {
	return strings.Split(version, "(")[0]
}
