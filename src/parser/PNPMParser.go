package parser

import (
	"errors"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	"gopkg.in/yaml.v3"
)

func parsePNPM(lockFileData []byte) (types.LockFileInformation, error) {
	// Read lockfile version
	lockFileVersion, err := getPNPMLockfileVersion(lockFileData)
	if err != nil {
		return types.LockFileInformation{}, err
	}

	// Start the parsing process based on the lock file version
	switch lockFileVersion {
	case types.PNPM9:
		return parsePNPMV9(lockFileData)
	default:
		return types.LockFileInformation{}, errors.New("unsupported npm lock file version")
	}
}

func getPNPMLockfileVersion(lockFileData []byte) (types.NPMLockFileVersion, error) {
	type NPMLockVersionExcerpt struct {
		LockfileVersion string `yaml:"lockfileVersion,omitempty"`
	}
	var data NPMLockVersionExcerpt

	err := yaml.Unmarshal(lockFileData, &data)
	if err != nil {
		return types.PNPM1, errors.New("unsupported npm lock file version")
	}

	switch data.LockfileVersion {
	case "1.0":
		return types.PNPM1, nil
	case "2.0":
		return types.PNPM2, nil
	case "3.0":
		return types.PNPM3, nil
	case "4.0":
		return types.PNPM4, nil
	case "5.0":
		return types.PNPM5, nil
	case "6.0":
		return types.PNPM6, nil
	case "7.0":
		return types.PNPM7, nil
	case "8.0":
		return types.PNPM8, nil
	case "9.0":
		return types.PNPM9, nil
	case "10.0":
		return types.PNPM10, nil
	default:
		return types.PNPM10, errors.New("unsupported npm lock file version")
	}
}
