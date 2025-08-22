package main

import (
	"context"
	"log"
	"os"
	"time"

	plugin "github.com/CodeClarityCE/plugin-sbom-javascript/src"
	"github.com/CodeClarityCE/utility-types/ecosystem"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	plugin_db "github.com/CodeClarityCE/utility-types/plugin_db"
	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
)

// JSSBOMAnalysisHandler implements the AnalysisHandler interface
type JSSBOMAnalysisHandler struct{}

// StartAnalysis implements the AnalysisHandler interface
func (h *JSSBOMAnalysisHandler) StartAnalysis(
	databases *ecosystem.PluginDatabases,
	dispatcherMessage types_amqp.DispatcherPluginMessage,
	config plugin_db.Plugin,
	analysisDoc codeclarity.Analysis,
) (map[string]any, codeclarity.AnalysisStatus, error) {
	return startAnalysis(databases, dispatcherMessage, config, analysisDoc)
}

// main is the entry point of the program.
func main() {
	pluginBase, err := ecosystem.NewPluginBase()
	if err != nil {
		log.Fatalf("Failed to initialize plugin base: %v", err)
	}
	defer pluginBase.Close()

	// Start the plugin with our analysis handler
	handler := &JSSBOMAnalysisHandler{}
	err = pluginBase.Listen(handler)
	if err != nil {
		log.Fatalf("Failed to start plugin: %v", err)
	}
}

// startAnalysis is a function that performs the analysis of a project and generates an SBOM (Software Bill of Materials).
// It takes the following parameters:
// - args: Arguments for the analysis.
// - dispatcherMessage: DispatcherPluginMessage containing information about the analysis.
// - config: Plugin configuration.
// - analysis_document: Analysis document containing the analysis configuration.
// It returns a map[string]any containing the result of the analysis, the analysis status, and an error if any.
func startAnalysis(databases *ecosystem.PluginDatabases, dispatcherMessage types_amqp.DispatcherPluginMessage, config plugin_db.Plugin, analysis_document codeclarity.Analysis) (map[string]any, codeclarity.AnalysisStatus, error) {

	// Get analysis config
	messageData := analysis_document.Config[config.Name].(map[string]any)

	// GET download path from ENV
	path := os.Getenv("DOWNLOAD_PATH")

	// Destination folder
	// destination := fmt.Sprintf("%s/%s/%s", path, organization, analysis.Commit)
	// Prepare the arguments for the plugin
	project := path + "/" + messageData["project"].(string)

	// Start the plugin
	sbomOutput := plugin.Start(project, analysis_document.Id)

	result := codeclarity.Result{
		Result:     sbom.ConvertSbomToMap(sbomOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	_, err := databases.Codeclarity.NewInsert().Model(&result).Exec(context.Background())
	if err != nil {
		panic(err)
	}

	// Prepare the result to store in step
	// In this case we only store the sbomKey
	// The other plugins will use this key to get the sbom
	res := make(map[string]any)
	res["sbomKey"] = result.Id

	// The output is always a map[string]any
	return res, sbomOutput.AnalysisInfo.Status, nil
}
