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

	// If no workspaces, build graph for default workspace
	if len(packageFile.WorkSpaces) == 0 {
		results[properties.DEFAULT_WORKSPACE_CHARACTER] = buildWorkspace(lockFile, packageFile)
		return results
	}

	// Build graph for each workspace
	for name := range projectInformation.WorkSpaces {
		workspacePackageFile := projectInformation.WorkSpacesPackageFileData[name]
		results[name] = buildWorkspace(lockFile, workspacePackageFile)
	}
	return results
}

func buildWorkspace(lockFile types.LockFileInformation, packageFile types.PackageFile) sbomTypes.WorkSpace {
	workSpace := sbomTypes.WorkSpace{
		Dependencies: make(map[string]map[string]sbomTypes.Versions),
		Start:        sbomTypes.Start{},
	}

	for dependency_name, dependency := range lockFile.Dependencies {
		for version, versionInfo := range dependency {
			resolvedFilePackage := sbomTypes.Versions{
				Key:          dependency_name + properties.VERSION_SEPERATOR + version,
				Requires:     versionInfo.Requires,
				Dependencies: versionInfo.Dependencies,
				Optional:     versionInfo.Optional,
				Bundled:      versionInfo.Bundled,
				Dev:          versionInfo.Dev,
				Transitive:   false,
			}

			if dep, dependency_already_present := workSpace.Dependencies[dependency_name]; dependency_already_present {
				if _, versiondependency_already_present := dep[version]; !versiondependency_already_present {
					workSpace.Dependencies[dependency_name][version] = resolvedFilePackage
				}
			} else {
				workSpace.Dependencies[dependency_name] = map[string]sbomTypes.Versions{
					version: resolvedFilePackage,
				}
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
					// dep := workSpace.Dependencies[name][version]
					// dep.Dev = true
					// workSpace.Dependencies[name][version] = dep

					// Append the startDep to the DevDependencies in the workSpace
					workSpace.Start.DevDependencies = append(workSpace.Start.DevDependencies, startDep)
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

					// Append the startDep to the DevDependencies in the workSpace
					workSpace.Start.Dependencies = append(workSpace.Start.Dependencies, startDep)
				}
			}
		}
	}
	return workSpace
}
