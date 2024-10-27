package parser

import (
	"encoding/json"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/resolver"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
)

func parseNPMV1(lockFileData []byte) (types.LockFileInformation, error) {
	var lockFile schemas.NPMLockFileV1

	err := json.Unmarshal(lockFileData, &lockFile)
	if err != nil {
		return types.LockFileInformation{}, err
	}
	return resolver.ResolveNPMV1(lockFile)
}
