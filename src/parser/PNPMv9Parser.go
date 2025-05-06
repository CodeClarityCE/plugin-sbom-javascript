package parser

import (
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/resolver"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
	"gopkg.in/yaml.v3"
)

func parsePNPMV9(lockFileData []byte) (types.LockFileInformation, error) {
	var lockFile schemas.PNPMLockFileV9

	err := yaml.Unmarshal(lockFileData, &lockFile)
	if err != nil {
		return types.LockFileInformation{}, err
	}
	return resolver.ResolvePNPMV9(lockFile)
}
