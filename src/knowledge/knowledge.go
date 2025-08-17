package knowledge

import (
	"encoding/json"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	"github.com/google/uuid"
)

func UpdateKnowledge(dependencies map[string]map[string]types.Versions, analysisId uuid.UUID) {
	dependencies_names := make([]string, 0, len(dependencies))
	for dependency_name := range dependencies {
		dependencies_names = append(dependencies_names, dependency_name)
	}

	// Send results
	sbom_message := types_amqp.SbomPackageFollowerMessage{
		AnalysisId:    analysisId,
		PackagesNames: dependencies_names,
		Language:      "javascript",
	}
	data, _ := json.Marshal(sbom_message)
	amqp_helper.Send("sbom_packageFollower", data)
}
