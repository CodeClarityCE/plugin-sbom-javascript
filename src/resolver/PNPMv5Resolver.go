package resolver

import (
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
)

// ResolvePNPMV5 builds the flat dependency graph for a 5.x-family pnpm lockfile.
// Unlike v9, the resolved graph lives inside each `packages` entry, so we iterate
// `packages` directly. Keys are `/name/version` with an optional `_peer@x.y.z`
// suffix (see cleanNameV5), and per-package dependency values may carry the same
// suffix (see stripPeerSuffixV5).
func ResolvePNPMV5(lockFile schemas.PNPMLockFileV5) (types.LockFileInformation, error) {
	LockFileInformation := types.LockFileInformation{
		Dependencies:    map[string]map[string]types.Versions{},
		PackageManager:  packageManager.PNPM,
		LockFileVersion: 5,
	}

	for key, pkg := range lockFile.Packages {
		if key == "" {
			continue
		}

		name, version := cleanNameV5(key)
		if name == "" || version == "" {
			continue
		}

		requires := make(map[string]string)
		for depName, depVersion := range pkg.Dependencies {
			requires[depName] = stripPeerSuffixV5(depVersion)
		}
		for depName, depVersion := range pkg.OptionalDependencies {
			requires[depName] = stripPeerSuffixV5(depVersion)
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

// cleanNameV5 extracts the package name and version from a 5.x-family package key
// of the form `/name/version` or `/name/version_peer@x.y.z`. The version never
// contains a slash, so the last `/` separates name from version; scoped names
// (`@scope/pkg`) are therefore preserved.
func cleanNameV5(key string) (string, string) {
	key = strings.TrimPrefix(key, "/")
	idx := strings.LastIndex(key, "/")
	if idx == -1 {
		return key, ""
	}
	name := key[:idx]
	version := stripPeerSuffixV5(key[idx+1:])
	return name, version
}

// stripPeerSuffixV5 drops the `_peer@x.y.z(+peer@x.y.z)` peer-resolution suffix
// that 5.x lockfiles append to versions, leaving the bare version.
func stripPeerSuffixV5(version string) string {
	return strings.Split(version, "_")[0]
}
