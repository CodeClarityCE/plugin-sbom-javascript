package parser

import (
	"encoding/json"
	"errors"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
)

func parseNPM(lockFileData []byte) (types.LockFileInformation, error) {
	// Read lockfile version
	lockFileVersion, err := getLockfileVersion(lockFileData)
	if err != nil {
		return types.LockFileInformation{}, err
	}

	// Start the parsing process based on the lock file version
	switch lockFileVersion {
	case types.NPMV1:
		return parseNPMV1(lockFileData)
	case types.NPMV2, types.NPMV3:
		return parseNPMV2(lockFileData) // NPM v2 and v3 have the same lock file format
	default:
		return types.LockFileInformation{}, errors.New("unsupported npm lock file version")
	}
}

func getLockfileVersion(lockFileData []byte) (types.NPMLockFileVersion, error) {
	type NPMLockVersionExcerpt struct {
		LockfileVersion int `json:"lockfileVersion,omitempty"`
	}
	var data NPMLockVersionExcerpt

	err := json.Unmarshal(lockFileData, &data)
	if err != nil {
		return types.NPMV1, errors.New("unsupported npm lock file version")
	}

	switch data.LockfileVersion {
	case 1:
		return types.NPMV1, nil
	case 2:
		return types.NPMV2, nil
	case 3:
		return types.NPMV3, nil
	default:
		return types.NPMV1, errors.New("unsupported npm lock file version")
	}
}
