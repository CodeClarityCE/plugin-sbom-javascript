package parser

import (
	"errors"
	"os"

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
		return parseYarn(lockFileData)
	default:
		return types.LockFileInformation{}, errors.New("unknown lock file type")
	}

}
