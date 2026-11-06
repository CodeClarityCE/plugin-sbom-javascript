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
	name, constraint := splitYarnSpecifier(specifier)
	return name + "@" + constraint
}

// splitYarnSpecifier splits "name@range" into the real name and range.
// Aliases are followed: "x-cjs@npm:x@^4.2.0" gives x and ^4.2.0.
func splitYarnSpecifier(specifier string) (string, string) {
	// Split on the first "@" that is not a scope prefix.
	at := strings.Index(specifier[1:], "@") + 1
	if at <= 0 {
		return specifier, ""
	}
	name, constraint := specifier[:at], strings.Replace(specifier[at+1:], "npm:", "", 1)
	if realName, aliasRange, isAlias := splitNpmAlias(constraint); isAlias {
		return realName, aliasRange
	}
	return name, constraint
}

// yarnEntryName returns an entry's real package name, following aliases.
func yarnEntryName(entryKey string) string {
	first, _, _ := strings.Cut(entryKey, ",")
	name, _ := splitYarnSpecifier(strings.Trim(strings.TrimSpace(first), `"`))
	return name
}

// resolveYarnTransitives links each package to the versions it depends on,
// using the version the lockfile recorded for each range.
func resolveYarnTransitives(lockFileInformation types.LockFileInformation, specifiers map[string]string) {
	fillDependencies(lockFileInformation.Dependencies, func(name, constraint string) (string, bool) {
		resolved, ok := specifiers[name+"@"+constraint]
		return resolved, ok
	})
}

// yarnResolveDirect finds a declared dependency's version by its "name@range".
func yarnResolveDirect(specifiers map[string]string) func(string, string, string) (string, string, bool) {
	return func(_ string, name, constraint string) (string, string, bool) {
		realName, realRange := splitYarnSpecifier(name + "@" + constraint)
		version, ok := specifiers[realName+"@"+realRange]
		return realName, version, ok
	}
}
