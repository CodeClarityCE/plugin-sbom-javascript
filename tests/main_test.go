package main

import (
	"testing"

	plugin "github.com/CodeClarityCE/plugin-sbom-javascript/src"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCreate(t *testing.T) {
	out := plugin.Start("/Users/cedric/Documents/workspace/codeclarity-dev/api", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func TestCreateNPMv1(t *testing.T) {
	out := plugin.Start("./npmv1", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./npmv1/sbom.json")
}

func TestCreateNPMv2(t *testing.T) {
	out := plugin.Start("./npmv2", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./npmv2/sbom.json")
}

func TestCreateNPMv3(t *testing.T) {
	out := plugin.Start("./npmv3", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./npmv3/sbom.json")
}

func TestCreateYarnv1(t *testing.T) {
	out := plugin.Start("./yarnv1", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./yarnv1/sbom.json")
}

func TestCreateYarnv2(t *testing.T) {
	out := plugin.Start("./yarnv2", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./yarnv2/sbom.json")
}

func TestCreateYarnv3(t *testing.T) {
	out := plugin.Start("./yarnv3", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./yarnv3/sbom.json")
}

func TestCreateYarnv4(t *testing.T) {
	out := plugin.Start("./yarnv4", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./yarnv4/sbom.json")
}

func TestCreateYarnWorkspace(t *testing.T) {
	out := plugin.Start("./yarn_workspace", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./yarn_workspace/sbom.json")
}

func TestCreatePNPMv10_10(t *testing.T) {
	out := plugin.Start("./pnpmv10.10", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./pnpmv10.10/sbom.json")
}

// You can adapt this test to your needs
func TestCreateTest(t *testing.T) {
	out := plugin.Start("./test", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./test/sbom.json")
}

// func BenchmarkCreate(b *testing.B) {
// 	// Get DB
// 	db, err := dbhelper.GetDatabase(dbhelper.Config.Database.Knowledge)
// 	if err != nil {
// 		log.Printf("%v", err)
// 	}

// 	out := js.Start("./vulnerable", db)

// 	// Assert the expected values
// 	assert.NotNil(b, out)
// 	assert.Equal(b, analysis.SUCCESS, out.AnalysisInfo.Status)
// 	assert.NotEmpty(b, out.WorkSpaces)
// }
