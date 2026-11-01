package parser

import (
	"errors"
	"strconv"
	"strings"

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
	case types.PNPM5, types.PNPM7:
		// 5.x family (pnpm 5-7): `/name/version` keys, `_peer` suffixes
		return parsePNPMV5(lockFileData)
	case types.PNPM6, types.PNPM8:
		// 6.x family (pnpm 8): `/name@version` keys, `(peer)` suffixes
		return parsePNPMV6(lockFileData)
	case types.PNPM9:
		return parsePNPMV9(lockFileData)
	default:
		return types.LockFileInformation{}, errors.New("unsupported pnpm lock file version")
	}
}

func getPNPMLockfileVersion(lockFileData []byte) (types.NPMLockFileVersion, error) {
	type NPMLockVersionExcerpt struct {
		LockfileVersion string `yaml:"lockfileVersion,omitempty"`
	}
	var data NPMLockVersionExcerpt

	err := yaml.Unmarshal(lockFileData, &data)
	if err != nil {
		return types.PNPM1, errors.New("unsupported pnpm lock file version")
	}

	// Real lockfiles carry minor versions (e.g. "5.3", "5.4", "6.0"), so dispatch
	// on the major component rather than matching the full string.
	major, err := strconv.Atoi(strings.Split(data.LockfileVersion, ".")[0])
	if err != nil {
		return types.PNPM1, errors.New("unsupported pnpm lock file version")
	}

	switch major {
	case 1:
		return types.PNPM1, nil
	case 2:
		return types.PNPM2, nil
	case 3:
		return types.PNPM3, nil
	case 4:
		return types.PNPM4, nil
	case 5:
		return types.PNPM5, nil
	case 6:
		return types.PNPM6, nil
	case 7:
		return types.PNPM7, nil
	case 8:
		return types.PNPM8, nil
	case 9:
		return types.PNPM9, nil
	case 10:
		return types.PNPM10, nil
	default:
		return types.PNPM10, errors.New("unsupported pnpm lock file version")
	}
}
