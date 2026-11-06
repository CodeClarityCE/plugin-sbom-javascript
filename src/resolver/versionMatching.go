package resolver

import (
	"log"
	"regexp"
	"sort"
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	semver "github.com/CodeClarityCE/utility-node-semver"
)

// highestSatisfying returns the highest version that matches the constraint.
// It is used when the lockfile does not say which version was installed.
func highestSatisfying(versions map[string]types.Versions, constraint string) (string, bool) {
	// If the version required is latest, we replace by a wildcard
	if constraint == "latest" {
		constraint = "*"
	}
	parsedConstraint, err := semver.ParseConstraint(constraint)
	if err != nil {
		log.Println("Cannot parse constraint ", constraint)
		parsedConstraint, _ = semver.ParseConstraint("*")
	}
	var satisfying []string
	for candidate := range versions {
		candidateSemver, err := semver.ParseSemver(candidate)
		if err != nil {
			log.Println("Cannot parse semver ", candidate)
			continue
		}
		if semver.Satisfies(candidateSemver, parsedConstraint, false) {
			satisfying = append(satisfying, candidate)
		}
	}
	if len(satisfying) == 0 {
		return "", false
	}
	// -1 sorts from highest to lowest.
	sorted, err := semver.SortStrings(-1, satisfying)
	if err != nil {
		return "", false
	}
	return sorted[0], true
}

// npmPackageName matches a valid npm package name, scoped or not.
// It rejects values like "git+ssh://git@host/repo".
var npmPackageName = regexp.MustCompile(`^(@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$`)

// splitNpmAlias reads an alias like "npm:string-width@^4.2.0" and returns
// the real package name and its range. ok is false for a normal range.
func splitNpmAlias(constraint string) (realName string, rangeOrVersion string, ok bool) {
	constraint = strings.TrimPrefix(constraint, "npm:")
	at := strings.LastIndex(constraint, "@")
	if at <= 0 {
		return "", "", false
	}
	realName = constraint[:at]
	if !npmPackageName.MatchString(realName) {
		return "", "", false
	}
	return realName, constraint[at+1:], true
}

// resolveRequirement returns the package and version a dependency points to.
// It follows aliases and prefers the version the lockfile recorded.
func resolveRequirement(dependencies map[string]map[string]types.Versions, requiredName, constraint string, recorded func(name, constraint string) (string, bool)) (name string, version string, ok bool) {
	constraint = strings.Replace(constraint, "npm:", "", 1)
	if realName, aliasRange, isAlias := splitNpmAlias(constraint); isAlias {
		requiredName, constraint = realName, aliasRange
	}
	versions, present := dependencies[requiredName]
	if !present {
		return "", "", false
	}
	if recorded != nil {
		if resolved, found := recorded(requiredName, constraint); found {
			if _, inLockfile := versions[resolved]; inLockfile {
				return requiredName, resolved, true
			}
		}
	}
	if _, exact := versions[constraint]; exact {
		return requiredName, constraint, true
	}
	best, found := highestSatisfying(versions, constraint)
	return requiredName, best, found
}

// fillDependencies links every package to the versions it depends on.
func fillDependencies(dependencies map[string]map[string]types.Versions, recorded func(name, constraint string) (string, bool)) {
	for _, packageVersions := range dependencies {
		for _, version := range packageVersions {
			requiredNames := sortedRequires(version.Requires)
			edges := newEdgeSetter(version.Dependencies)
			for _, requiredName := range requiredNames {
				constraint := version.Requires[requiredName]
				name, resolved, ok := resolveRequirement(dependencies, requiredName, constraint, recorded)
				if ok {
					edges.set(requiredName, name, resolved)
				}
			}
		}
	}
}

// sortedRequires returns the dependency names in sorted order.
func sortedRequires(requires map[string]string) []string {
	names := make([]string, 0, len(requires))
	for name := range requires {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// edgeSetter adds dependency links by real package name. If a normal
// dependency and an alias point to the same package, the normal one wins.
type edgeSetter struct {
	dependencies map[string]string
	fromAlias    map[string]bool
}

func newEdgeSetter(dependencies map[string]string) edgeSetter {
	return edgeSetter{dependencies: dependencies, fromAlias: map[string]bool{}}
}

func (e edgeSetter) set(requiredName, realName, version string) {
	isAlias := realName != requiredName
	if _, set := e.dependencies[realName]; set && isAlias && !e.fromAlias[realName] {
		return
	}
	e.dependencies[realName] = version
	e.fromAlias[realName] = isAlias
}

// HighestSatisfying is highestSatisfying for callers outside the package.
func HighestSatisfying(versions map[string]types.Versions, constraint string) (string, bool) {
	return highestSatisfying(versions, constraint)
}

// mergeRequires combines dependencies and optional dependencies in a new map.
func mergeRequires(dependencies, optionalDependencies map[string]string) map[string]string {
	requires := make(map[string]string, len(dependencies)+len(optionalDependencies))
	for name, constraint := range dependencies {
		requires[name] = constraint
	}
	for name, constraint := range optionalDependencies {
		requires[name] = constraint
	}
	return requires
}
