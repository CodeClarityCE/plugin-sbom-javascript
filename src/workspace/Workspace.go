package workspace

import (
	"log"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/properties"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	semver "github.com/CodeClarityCE/utility-node-semver"
)

func Build(lockFile types.LockFileInformation, projectInformation types.ProjectInformation) map[string]sbomTypes.WorkSpace {
	packageFile := projectInformation.PackageFileData
	results := map[string]sbomTypes.WorkSpace{}

	results[properties.DEFAULT_WORKSPACE_CHARACTER] = buildWorkspace(lockFile, packageFile)

	// If no workspaces then return
	if len(packageFile.WorkSpaces) == 0 {
		return results
	}

	// Build graph for each workspace
	for name := range projectInformation.WorkSpacesPackageFileData {
		workspacePackageFile := projectInformation.WorkSpacesPackageFileData[name]
		results[name] = buildWorkspace(lockFile, workspacePackageFile)
	}
	return results
}

func buildWorkspace(lockFile types.LockFileInformation, packageFile types.PackageFile) sbomTypes.WorkSpace {
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

	// Iterate over the devDependencies in the packageFile
	for name, constraint := range packageFile.DevDependencies {
		// Check if the dependency exists in the lockFile
		if versions, exists := lockFile.Dependencies[name]; exists {
			// Iterate over the versions of the dependency
			for version := range versions {
				// Parse the constraint and handle any errors
				parsedConstraint, err := semver.ParseConstraint(constraint)
				if err != nil {
					log.Println("Error parsing constraint", err)
					continue
				}

				// Parse the version and handle any errors
				parsedVersion, err := semver.ParseSemver(version)
				if err != nil {
					log.Println("Error parsing version", err)
					continue
				}

				// Check if the parsed version satisfies the parsed constraint
				if semver.Satisfies(parsedVersion, parsedConstraint, false) {
					// Create a WorkSpaceDependency with the name, version, and constraint
					startDep := sbomTypes.WorkSpaceDependency{
						Name:       name,
						Version:    version,
						Constraint: constraint,
					}

					// Append the startDep to the DevDependencies in the workSpace
					workspace.Start.DevDependencies = append(workspace.Start.DevDependencies, startDep)
				}
			}
		}
	}

	for name, constraint := range packageFile.Dependencies {
		// Check if the dependency exists in the lockFile
		if versions, exists := lockFile.Dependencies[name]; exists {
			// Iterate over the versions of the dependency
			for version := range versions {
				// Parse the constraint and handle any errors
				parsedConstraint, err := semver.ParseConstraint(constraint)
				if err != nil {
					log.Println("Error parsing constraint", err)
					continue
				}

				// Parse the version and handle any errors
				parsedVersion, err := semver.ParseSemver(version)
				if err != nil {
					log.Println("Error parsing version", err)
					continue
				}

				// Check if the parsed version satisfies the parsed constraint
				if semver.Satisfies(parsedVersion, parsedConstraint, false) {
					// Create a WorkSpaceDependency with the name, version, and constraint
					startDep := sbomTypes.WorkSpaceDependency{
						Name:       name,
						Version:    version,
						Constraint: constraint,
					}

					// Append the startDep to the Dependencies in the workSpace
					workspace.Start.Dependencies = append(workspace.Start.Dependencies, startDep)
				}
			}
		}
	}

	workspace = tagDevDependencies(workspace)

	return workspace
}

func tagDevDependencies(workspace sbomTypes.WorkSpace) sbomTypes.WorkSpace {

	// Iterate over the devDependencies in the packageFile
	for _, startDevDependency := range workspace.Start.DevDependencies {
		dependencyInformation := workspace.Dependencies[startDevDependency.Name][startDevDependency.Version]
		dependencyInformation.Dev = true
		workspace.Dependencies[startDevDependency.Name][startDevDependency.Version] = dependencyInformation
		workspace = recursivelytagDev(dependencyInformation, workspace)
	}

	// Iterate over the dependencies in the packageFile
	for _, startDependency := range workspace.Start.Dependencies {
		dependencyInformation := workspace.Dependencies[startDependency.Name][startDependency.Version]
		dependencyInformation.Prod = true
		workspace.Dependencies[startDependency.Name][startDependency.Version] = dependencyInformation
		workspace = recursivelytagProd(dependencyInformation, workspace)
	}

	return workspace
}

func recursivelytagDev(currentDependency sbomTypes.Versions, workspace sbomTypes.WorkSpace) sbomTypes.WorkSpace {
	for childName, childVersion := range currentDependency.Dependencies {
		child := workspace.Dependencies[childName][childVersion]

		// If child has already been analyzed (loop)
		// then do not recurse
		if child.Dev == true {
			continue
		}

		child.Dev = true
		workspace.Dependencies[childName][childVersion] = child
		workspace = recursivelytagDev(child, workspace)
	}
	return workspace
}

func recursivelytagProd(currentDependency sbomTypes.Versions, workspace sbomTypes.WorkSpace) sbomTypes.WorkSpace {
	for childName, childVersion := range currentDependency.Dependencies {
		child := workspace.Dependencies[childName][childVersion]

		// If child has already been analyzed (loop)
		// then do not recurse
		if child.Prod == true {
			continue
		}

		child.Prod = true
		workspace.Dependencies[childName][childVersion] = child
		workspace = recursivelytagProd(child, workspace)
	}
	return workspace
}
