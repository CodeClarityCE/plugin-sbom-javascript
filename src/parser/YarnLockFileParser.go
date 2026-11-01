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
	content := string(lockFileData)

	// Classic Yarn v1 lockfiles always carry this comment in the header.
	if strings.Contains(content, "yarn lockfile v1") {
		return types.YarnV1, nil
	}

	// Yarn Berry (v2+) lockfiles are YAML and always start with a `__metadata:`
	// block carrying a `version:` cache-key. That cache-key has churned across
	// releases (4, 5, 6, 7, 8, ...) and does NOT map 1:1 to the Yarn major
	// version, so keying off its exact value is fragile (the previous logic only
	// recognised 4/6/8 and rejected everything else). The V2/V3/V4 parsers are
	// identical apart from their generated type name, so route every Berry
	// lockfile through the V4 path — detect Berry structurally, not by number.
	if strings.Contains(content, "__metadata:") {
		return types.YarnV4, nil
	}

	return types.YarnV1, errors.New("unsupported yarn lock file version")
}
