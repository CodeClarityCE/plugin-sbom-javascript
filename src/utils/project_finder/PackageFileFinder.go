package project_finder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
)

func ReadPackageFiles(directory string) (projectInformation types.ProjectInformation, err error) {
	directory = filepath.Clean(directory)

	all_projects := findProjects(directory)

	// Verify that there is a package.json and lock file pair
	project, ok := all_projects[directory]
	if !ok {
		return project, fmt.Errorf("no package.json and lock file pair found")
	}
	if project.LockFile == "" {
		return project, fmt.Errorf("no lock file found")
	}

	// Parse the package file
	packageFileData, err := os.ReadFile(project.PackageFile)
	if err != nil {
		return project, err
	}
	var packageFile types.PackageFile
	err = json.Unmarshal(packageFileData, &packageFile)
	if err != nil {
		return project, err
	}

	project.PackageFileData = packageFile
	project.WorkSpacesPackageFileData = make(map[string]types.PackageFile)

	// If lockfile contains workspaces
	for _, workspace := range packageFile.WorkSpaces {
		// Find and read the lockfiles
		if strings.Contains(workspace, "*") {
			root := filepath.Join(directory, strings.ReplaceAll(workspace, "*", ""))
			for workspace_found := range all_projects {
				if strings.Contains(workspace_found, root) {
					path := filepath.Join(workspace_found, "package.json")
					packageFileData, err := os.ReadFile(path)
					if err != nil {
						return project, err
					}
					// Parse the package file
					var workspacePackageFile types.PackageFile
					err = json.Unmarshal(packageFileData, &workspacePackageFile)
					if err != nil {
						return project, err
					}
					// Add the workspace package file to the package manifest
					workspace_name := strings.ReplaceAll(workspace_found, directory+"/", "")
					project.WorkSpacesPackageFileData[workspace_name] = workspacePackageFile
				}
			}

		} else {
			path := filepath.Join(directory, workspace, "package.json")
			packageFileData, err := os.ReadFile(path)
			if err != nil {
				return project, err
			}
			// Parse the package file
			var workspacePackageFile types.PackageFile
			err = json.Unmarshal(packageFileData, &workspacePackageFile)
			if err != nil {
				return project, err
			}
			// Add the workspace package file to the package manifest
			project.WorkSpacesPackageFileData[workspace] = workspacePackageFile
		}
	}

	return project, nil

}

func findProjects(directory string) map[string]types.ProjectInformation {
	directoriesToSkip := []string{".git", "node_modules", ".yarn"}
	lockfiles := []string{"yarn.lock", "package-lock.json", "pnpm-lock.yaml"}
	all_projects := make(map[string]types.ProjectInformation)

	filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			// Skip some directories
			for _, dir := range directoriesToSkip {
				if d.Name() == dir {
					return filepath.SkipDir
				}
			}
			return nil
		}

		dir := filepath.Dir(path)
		relative_path := filepath.Join(filepath.Base(dir), filepath.Base(path))

		// Check if the file is a lock file
		for _, lockfile := range lockfiles {
			if d.Name() == lockfile {
				project := all_projects[dir]
				project.LockFile = path
				project.RelativeLockFilePath = relative_path
				all_projects[dir] = project
				break
			}
		}

		switch d.Name() {
		case "package.json":
			project := all_projects[dir]
			project.PackageFile = path
			project.RelativePackagePath = relative_path
			all_projects[dir] = project
		case "yarn.lock":
			project := all_projects[dir]
			project.PackageManager = packageManager.YARN
			all_projects[dir] = project
		case "package-lock.json":
			project := all_projects[dir]
			project.PackageManager = packageManager.NPM
			all_projects[dir] = project
		case "pnpm-lock.yaml":
			project := all_projects[dir]
			project.PackageManager = packageManager.PNPM
			all_projects[dir] = project
		}

		return nil
	})
	return all_projects
}
