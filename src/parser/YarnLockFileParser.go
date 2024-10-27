package parser

import (
	"errors"
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/resolver"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
	"gopkg.in/yaml.v3"
)

func parseYarn(lockFileData []byte) (types.LockFileInformation, error) {

	lockFileVersion, err := getYARNLockFileVersion(lockFileData)

	if err != nil {
		return types.LockFileInformation{}, err
	}

	switch lockFileVersion {
	case types.YarnV1:
		return parseYarnV1(lockFileData)
	case types.YarnV2:
		return parseYarnV2(lockFileData)
	case types.YarnV3:
		return parseYarnV3(lockFileData)
	case types.YarnV4:
		return parseYarnV4(lockFileData)
	default:
		return types.LockFileInformation{}, errors.New("unsupported yarn lock file version")
	}
}

func parseYarnV1(lockFileData []byte) (types.LockFileInformation, error) {
	parsedLockfile, err := ParseLockFileData(lockFileData)
	if err != nil {
		return types.LockFileInformation{}, err
	}
	return resolver.ResolveYarnv1(parsedLockfile)
}

func parseYarnV2(lockFileData []byte) (types.LockFileInformation, error) {
	var data schemas.YarnV2LockFile

	if err := yaml.Unmarshal(lockFileData, &data); err != nil {
		return types.LockFileInformation{}, err
	}

	delete(data, "__metadata")

	return resolver.ResolveYarnv2(data)
}

func parseYarnV3(lockFileData []byte) (types.LockFileInformation, error) {
	var data schemas.YarnV3LockFile

	if err := yaml.Unmarshal(lockFileData, &data); err != nil {
		return types.LockFileInformation{}, err
	}

	delete(data, "__metadata")

	return resolver.ResolveYarnv3(data)
}

func parseYarnV4(lockFileData []byte) (types.LockFileInformation, error) {
	var data schemas.YarnV4LockFile

	if err := yaml.Unmarshal(lockFileData, &data); err != nil {
		return types.LockFileInformation{}, err
	}

	delete(data, "__metadata")

	return resolver.ResolveYarnv4(data)
}

func getYARNLockFileVersion(lockFileData []byte) (types.YarnLockFileVersion, error) {
	header_byte := make([]byte, 180)
	copy(header_byte, lockFileData[:180])
	header := string(header_byte)

	lines := strings.Split(header, "\n")
	versionLine := lines[1][len(lines[1])-2:]
	metaDataVersionLine := strings.TrimSpace(lines[4])
	version := metaDataVersionLine[len(metaDataVersionLine)-1:]

	switch {
	case versionLine == "v1":
		return types.YarnV1, nil
	case version == "4":
		return types.YarnV2, nil
	case version == "6":
		return types.YarnV3, nil
	case version == "8":
		return types.YarnV4, nil
	default:
		return types.YarnV1, errors.New("unsupported yarn lock file version")
	}
}
