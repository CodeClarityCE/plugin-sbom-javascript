package parser

import (
	"encoding/json"
	"log"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/resolver"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"
)

func parseNPMV2(lockFileData []byte) (types.LockFileInformation, error) {
	var lockFile schemas.NPMLockFileV2

	err := json.Unmarshal(lockFileData, &lockFile)
	if err != nil {
		log.Println(err)
		return types.LockFileInformation{}, err
	}

	return resolver.ResolveNPMV2(lockFile)
}
