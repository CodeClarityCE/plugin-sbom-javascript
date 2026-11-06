package main

import (
	"testing"

	plugin "github.com/CodeClarityCE/plugin-sbom-javascript/src"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

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

func TestCreatePNPMv5(t *testing.T) {
	out := plugin.Start("./pnpmv5", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./pnpmv5/sbom.json")
}

func TestCreatePNPMv6(t *testing.T) {
	out := plugin.Start("./pnpmv6", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./pnpmv6/sbom.json")
}

func TestCreatePNPMv10_10(t *testing.T) {
	out := plugin.Start("./pnpmv10.10", uuid.UUID{})

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	writeJSON(out, "./pnpmv10.10/sbom.json")
}

// pnpm 11+ adds an env lockfile document before the project lockfile.
// The SBOM must list the project's dependencies, not pnpm itself.
func TestCreatePNPMv12EnvLockfile(t *testing.T) {
	out := plugin.Start("./pnpmv12_env_lockfile", uuid.UUID{})

	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	deps := out.WorkSpaces["."].Dependencies
	assert.Contains(t, deps, "dotenv")
	assert.Contains(t, deps, "debug")
	assert.NotContains(t, deps, "pnpm")
	assert.True(t, deps["dotenv"]["16.6.1"].Direct)
	assert.True(t, deps["debug"]["4.4.3"].Direct)
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

// A pnpm version like "8.3.6(typescript@5.6.3)" must resolve to 8.3.6 on every run.
func TestCreatePNPMv9PeerSuffixResolvesPinnedVersion(t *testing.T) {
	for i := 0; i < 50; i++ {
		out := plugin.Start("./pnpmv9_peer_suffix", uuid.UUID{})

		assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
		deps := out.WorkSpaces["."].Dependencies
		if !assert.Equal(t, "8.3.6", deps["a"]["1.0.0"].Dependencies["cosmiconfig"], "run %d", i) {
			return
		}
		assert.Equal(t, "6.0.0", deps["b"]["1.0.0"].Dependencies["cosmiconfig"], "run %d", i)
		assert.True(t, deps["cosmiconfig"]["8.3.6"].Transitive, "run %d", i)
	}
}

// Start lists must be sorted so the same input gives the same SBOM.
func TestCreatePNPMv9StartListIsSorted(t *testing.T) {
	for i := 0; i < 50; i++ {
		out := plugin.Start("./pnpmv9_peer_suffix", uuid.UUID{})

		var names []string
		for _, dep := range out.WorkSpaces["."].Start.Dependencies {
			names = append(names, dep.Name+"@"+dep.Version)
		}
		if !assert.Equal(t, []string{"a@1.0.0", "b@1.0.0", "typescript@5.6.3"}, names, "run %d", i) {
			return
		}
	}
}
