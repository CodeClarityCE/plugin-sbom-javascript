package workspace

import (
	"log"
	"sort"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/properties"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/resolver"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	semver "github.com/CodeClarityCE/utility-node-semver"
)

func Build(lockFile types.LockFileInformation, projectInformation types.ProjectInformation) map[string]sbomTypes.WorkSpace {
	packageFile := projectInformation.PackageFileData
	results := map[string]sbomTypes.WorkSpace{}

	results[properties.DEFAULT_WORKSPACE_CHARACTER] = buildWorkspace(lockFile, packageFile, properties.DEFAULT_WORKSPACE_CHARACTER)

	// If no workspaces then return
	if len(packageFile.WorkSpaces) == 0 {
		return results
	}

	// Build graph for each workspace
	for name := range projectInformation.WorkSpacesPackageFileData {
		workspacePackageFile := projectInformation.WorkSpacesPackageFileData[name]
		results[name] = buildWorkspace(lockFile, workspacePackageFile, name)
	}
	return results
}

func buildWorkspace(lockFile types.LockFileInformation, packageFile types.PackageFile, workspacePath string) sbomTypes.WorkSpace {
	// Init workspace structure
	workspace := sbomTypes.WorkSpace{
		Dependencies: make(map[string]map[string]sbomTypes.Versions),
		Start:        sbomTypes.Start{},
	}

	// Fill the information in workspace.Dependencies
	for dependency_name, dependency := range lockFile.Dependencies {
		for version, versionInfo := range dependency {
			resolvedFilePackage := sbomTypes.Versions{
				Key:          dependency_name + properties.VERSION_SEPERATOR + version,
				Requires:     versionInfo.Requires,
				Dependencies: versionInfo.Dependencies,
				Optional:     versionInfo.Optional, // Already present in NPM but not YARN
				Bundled:      versionInfo.Bundled,  // Already present in NPM but not YARN
				Dev:          versionInfo.Dev,      // Already present in NPM but not YARN
				Prod:         false,                // will be filled later
				Direct:       false,                // will be filled later
				Transitive:   false,                // will be filled later
			}

			if _, ok := workspace.Dependencies[dependency_name]; !ok {
				workspace.Dependencies[dependency_name] = map[string]sbomTypes.Versions{
					version: resolvedFilePackage,
				}
			} else {
				workspace.Dependencies[dependency_name][version] = resolvedFilePackage
			}
		}
	}

	workspace.Start.DevDependencies = startDependencies(lockFile, workspacePath, packageFile.DevDependencies)
	workspace.Start.Dependencies = startDependencies(lockFile, workspacePath, packageFile.Dependencies)

	// Sort so the same lockfile always gives the same SBOM.
	sortStartDependencies(workspace.Start.Dependencies)
	sortStartDependencies(workspace.Start.DevDependencies)

	workspace = tagDevDependencies(workspace)
	if lockFile.DevFlags {
		workspace = applyLockfileDevFlags(lockFile, workspace)
	}

	return workspace
}

// startDependencies returns the installed version of each declared dependency.
// If the lockfile does not record it, it uses the highest matching version.
func startDependencies(lockFile types.LockFileInformation, workspacePath string, declared map[string]string) []sbomTypes.WorkSpaceDependency {
	var starts []sbomTypes.WorkSpaceDependency
	for name, constraint := range declared {
		if lockFile.ResolveDirect != nil {
			if realName, version, ok := lockFile.ResolveDirect(workspacePath, name, constraint); ok {
				if _, inLockfile := lockFile.Dependencies[realName][version]; inLockfile {
					starts = append(starts, sbomTypes.WorkSpaceDependency{Name: realName, Version: version, Constraint: constraint})
					continue
				}
			}
		}
		versions, exists := lockFile.Dependencies[name]
		if !exists {
			continue
		}
		if _, err := semver.ParseConstraint(constraint); err != nil {
			log.Println("Error parsing constraint", err)
			continue
		}
		if version, ok := resolver.HighestSatisfying(versions, constraint); ok {
			starts = append(starts, sbomTypes.WorkSpaceDependency{Name: name, Version: version, Constraint: constraint})
		}
	}
	return starts
}

func sortStartDependencies(deps []sbomTypes.WorkSpaceDependency) {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
}

func tagDevDependencies(workspace sbomTypes.WorkSpace) sbomTypes.WorkSpace {
	// Each traversal has its own visited set, so a package reached by both is tagged both.
	devSeen := map[string]bool{}
	for _, start := range workspace.Start.DevDependencies {
		workspace = tagDirect(workspace, start, func(v *sbomTypes.Versions) { v.Dev = true }, devSeen)
	}
	prodSeen := map[string]bool{}
	for _, start := range workspace.Start.Dependencies {
		workspace = tagDirect(workspace, start, func(v *sbomTypes.Versions) { v.Prod = true }, prodSeen)
	}
	return workspace
}

// applyLockfileDevFlags trusts the lockfile when it marks a package dev-only.
func applyLockfileDevFlags(lockFile types.LockFileInformation, workspace sbomTypes.WorkSpace) sbomTypes.WorkSpace {
	for name, versions := range lockFile.Dependencies {
		for version, info := range versions {
			if pkg, ok := workspace.Dependencies[name][version]; ok && info.Dev && pkg.Prod {
				pkg.Prod = false
				workspace.Dependencies[name][version] = pkg
			}
		}
	}
	return workspace
}

func tagDirect(workspace sbomTypes.WorkSpace, start sbomTypes.WorkSpaceDependency, tag func(*sbomTypes.Versions), seen map[string]bool) sbomTypes.WorkSpace {
	info := workspace.Dependencies[start.Name][start.Version]
	tag(&info)
	info.Direct = true
	workspace.Dependencies[start.Name][start.Version] = info
	return tagReachable(workspace, start.Name, start.Version, tag, seen)
}

// tagReachable tags every package below name@version, visiting each one once.
func tagReachable(workspace sbomTypes.WorkSpace, name, version string, tag func(*sbomTypes.Versions), seen map[string]bool) sbomTypes.WorkSpace {
	key := name + properties.VERSION_SEPERATOR + version
	if seen[key] {
		return workspace
	}
	seen[key] = true
	for childName, childVersion := range workspace.Dependencies[name][version].Dependencies {
		child := workspace.Dependencies[childName][childVersion]
		tag(&child)
		child.Transitive = true
		workspace.Dependencies[childName][childVersion] = child
		workspace = tagReachable(workspace, childName, childVersion, tag, seen)
	}
	return workspace
}
