package parser

import (
	"errors"
	"os"
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
)

func ParseLockFile(projectInformation types.ProjectInformation) (types.LockFileInformation, error) {
	// Read the lock file data
	lockFileData, err := os.ReadFile(projectInformation.LockFile)
	if err != nil {
		return types.LockFileInformation{}, err
	}

	// Determine the package manager and parse the lock file accordingly
	switch projectInformation.PackageManager {
	case packageManager.NPM:
		return parseNPM(lockFileData)
	case packageManager.YARN:
		parsed, err := parseYarn(lockFileData)
		if err != nil {
			return types.LockFileInformation{}, err
		}

		for dependency_name := range parsed.Dependencies {
			for version := range parsed.Dependencies[dependency_name] {
				if strings.Contains(version, "-use.local") {
					delete(parsed.Dependencies, dependency_name)
				}
			}
		}
		return parsed, err
	default:
		return types.LockFileInformation{}, errors.New("unknown lock file type")
	}

}
