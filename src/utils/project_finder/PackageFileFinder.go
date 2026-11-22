package project_finder

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

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

	// Workspace paths come from the project's own files, so reads stay inside the project.
	projectRoot, err := os.OpenRoot(directory)
	if err != nil {
		return project, err
	}
	defer projectRoot.Close()

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

	// pnpm lists workspaces in pnpm-workspace.yaml, not package.json.
	var excluded []string
	if project.PackageManager == packageManager.PNPM && len(packageFile.WorkSpaces) == 0 {
		included, negated, err := readPnpmWorkspacePatterns(projectRoot)
		if err != nil {
			return project, err
		}
		packageFile.WorkSpaces = included
		excluded = negated
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
					relative, err := filepath.Rel(directory, workspace_found)
					if err != nil {
						return project, err
					}
					packageFileData, err := projectRoot.ReadFile(filepath.Join(relative, "package.json"))
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
			packageFileData, err := projectRoot.ReadFile(filepath.Join(workspace, "package.json"))
			if err != nil {
				// Skip missing workspace directories and ones outside the project
				continue
			}
			// Parse the package file
			var workspacePackageFile types.PackageFile
			err = json.Unmarshal(packageFileData, &workspacePackageFile)
			if err != nil {
				// Skip workspaces with invalid package.json
				continue
			}
			// Add the workspace package file to the package manifest
			project.WorkSpacesPackageFileData[workspace] = workspacePackageFile
		}
	}

	for name := range project.WorkSpacesPackageFileData {
		if matchesAnyWorkspacePattern(name, excluded) {
			delete(project.WorkSpacesPackageFileData, name)
		}
	}

	return project, nil
}

// readPnpmWorkspacePatterns reads the package patterns in pnpm-workspace.yaml.
// Patterns starting with "!" are returned separately, as exclusions.
func readPnpmWorkspacePatterns(root *os.Root) (included []string, excluded []string, err error) {
	data, err := root.ReadFile("pnpm-workspace.yaml")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var manifest struct {
		Packages []string `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, nil, fmt.Errorf("parsing pnpm-workspace.yaml: %w", err)
	}
	for _, pattern := range manifest.Packages {
		if negated, ok := strings.CutPrefix(pattern, "!"); ok {
			excluded = append(excluded, strings.TrimPrefix(negated, "./"))
		} else {
			included = append(included, pattern)
		}
	}
	return included, excluded, nil
}

// matchesAnyWorkspacePattern reports whether name matches any pattern.
// A trailing "/**" also matches everything below the directory.
func matchesAnyWorkspacePattern(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if prefix, ok := strings.CutSuffix(pattern, "/**"); ok {
			if name == prefix || strings.HasPrefix(name, prefix+"/") {
				return true
			}
			continue
		}
		if matched, _ := path.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

func findProjects(directory string) map[string]types.ProjectInformation {
	directoriesToSkip := []string{".git", "node_modules", ".yarn"}
	lockfiles := []string{"yarn.lock", "package-lock.json", "pnpm-lock.yaml"}
	all_projects := make(map[string]types.ProjectInformation)

	err := filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
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
	if err != nil {
		// Keep what was found before the walk stopped.
		log.Printf("Stopped searching %s for projects: %v", directory, err)
	}
	return all_projects
}
