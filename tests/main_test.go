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

// When a range matches several versions, use the one the lockfile recorded.
func assertOverlappingRangesResolved(t *testing.T, dir string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		out := plugin.Start(dir, uuid.UUID{})

		assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
		deps := out.WorkSpaces["."].Dependencies
		if !assert.Equal(t, "4.3.4", deps["a"]["1.0.0"].Dependencies["debug"], "run %d", i) {
			return
		}
		assert.Equal(t, "4.1.0", deps["b"]["1.0.0"].Dependencies["debug"], "run %d", i)
	}
}

func TestCreateYarnv1OverlappingRangesUseLockfileResolution(t *testing.T) {
	assertOverlappingRangesResolved(t, "./yarnv1_overlapping_ranges")
}

func TestCreateYarnv4OverlappingRangesUseLockfileResolution(t *testing.T) {
	assertOverlappingRangesResolved(t, "./yarnv4_overlapping_ranges")
}

// "a" must use the debug nested under it, not the top-level one.
func TestCreateNPMv3NestedResolutionUsesInstallPath(t *testing.T) {
	assertOverlappingRangesResolved(t, "./npmv3_nested_resolution")
}

func TestCreateNPMv1NestedResolutionUsesInstallPath(t *testing.T) {
	assertOverlappingRangesResolved(t, "./npmv1_nested_resolution")
}

// With two peer variants of p@1.0.0, the first one sorted must win every run.
func TestCreatePNPMv9PeerVariantsPickStableSnapshot(t *testing.T) {
	for i := 0; i < 50; i++ {
		out := plugin.Start("./pnpmv9_peer_variants", uuid.UUID{})

		deps := out.WorkSpaces["."].Dependencies
		if !assert.Equal(t, "5.9.3", deps["p"]["1.0.0"].Dependencies["typescript"], "run %d", i) {
			return
		}
	}
}

// pnpm workspaces come from pnpm-workspace.yaml, and "!" patterns exclude.
func TestCreatePNPMv9WorkspaceFromPnpmWorkspaceYaml(t *testing.T) {
	out := plugin.Start("./pnpmv9_workspace", uuid.UUID{})

	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	if assert.Contains(t, out.WorkSpaces, "packages/app") {
		assert.True(t, out.WorkSpaces["packages/app"].Dependencies["y"]["1.0.0"].Direct)
		assert.True(t, out.WorkSpaces["packages/app"].Dependencies["y"]["1.0.0"].Prod)
	}
	assert.NotContains(t, out.WorkSpaces, "packages/ignored")
	assert.False(t, out.WorkSpaces["."].Dependencies["y"]["1.0.0"].Direct)
	assert.True(t, out.WorkSpaces["."].Dependencies["x"]["1.0.0"].Direct)
}

// An npm alias must show up as the real package, whatever the key order.
func assertAliasResolvesToRealPackage(t *testing.T, dir string) {
	t.Helper()
	out := plugin.Start(dir, uuid.UUID{})

	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	deps := out.WorkSpaces["."].Dependencies
	assert.Contains(t, deps, "string-width")
	assert.NotContains(t, deps, "string-width-cjs")
	assert.Equal(t, map[string]string{"string-width": "4.2.3"}, deps["a"]["1.0.0"].Dependencies)
	assert.True(t, deps["string-width"]["4.2.3"].Transitive)
}

func TestCreateYarnv1NpmAliasResolvesToRealPackage(t *testing.T) {
	assertAliasResolvesToRealPackage(t, "./yarnv1_npm_alias")
}

func TestCreateYarnv4NpmAliasResolvesToRealPackage(t *testing.T) {
	assertAliasResolvesToRealPackage(t, "./yarnv4_npm_alias")
}

// pnpm records an aliased dependency as "alias: real-name@version".
func TestCreatePNPMv9NpmAliasResolvesToRealPackage(t *testing.T) {
	out := plugin.Start("./pnpmv9_npm_alias", uuid.UUID{})

	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	deps := out.WorkSpaces["."].Dependencies
	assert.Equal(t, map[string]string{"@docusaurus/react-loadable": "6.0.0"}, deps["a"]["1.0.0"].Dependencies)
	assert.True(t, deps["@docusaurus/react-loadable"]["6.0.0"].Transitive)
	assert.True(t, deps["@docusaurus/react-loadable"]["6.0.0"].Prod)
}

// npm v2/v3 put an alias at node_modules/<alias>, with the real "name".
func TestCreateNPMv3NpmAliasResolvesToRealPackage(t *testing.T) {
	assertAliasResolvesToRealPackage(t, "./npmv3_npm_alias")
}

// npm v1 stores an alias's real package in "version".
func TestCreateNPMv1NpmAliasResolvesToRealPackage(t *testing.T) {
	assertAliasResolvesToRealPackage(t, "./npmv1_npm_alias")
}

// pnpm v9 optional dependencies must be linked and flagged optional.
func TestCreatePNPMv9OptionalDependencies(t *testing.T) {
	out := plugin.Start("./pnpmv9_optional_dependencies", uuid.UUID{})

	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	deps := out.WorkSpaces["."].Dependencies
	assert.Equal(t, map[string]string{"fsevents": "2.3.3"}, deps["a"]["1.0.0"].Dependencies)
	assert.True(t, deps["fsevents"]["2.3.3"].Optional)
	assert.True(t, deps["fsevents"]["2.3.3"].Transitive)
}

// Only the installed version is direct. debug@4.1.0, pinned by b,
// also matches the range but must stay transitive.
func assertDirectDependencyUsesLockfileResolution(t *testing.T, dir string) {
	t.Helper()
	out := plugin.Start(dir, uuid.UUID{})

	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	var debugStarts []string
	for _, d := range out.WorkSpaces["."].Start.Dependencies {
		if d.Name == "debug" {
			debugStarts = append(debugStarts, d.Version)
		}
	}
	assert.Equal(t, []string{"4.3.4"}, debugStarts)
	deps := out.WorkSpaces["."].Dependencies
	assert.True(t, deps["debug"]["4.3.4"].Direct)
	assert.False(t, deps["debug"]["4.1.0"].Direct)
	assert.True(t, deps["debug"]["4.1.0"].Transitive)
}

func TestCreateYarnv1DirectDependencyUsesLockfileResolution(t *testing.T) {
	assertDirectDependencyUsesLockfileResolution(t, "./yarnv1_direct_resolution")
}

func TestCreateNPMv3DirectDependencyUsesLockfileResolution(t *testing.T) {
	assertDirectDependencyUsesLockfileResolution(t, "./npmv3_direct_resolution")
}

func TestCreatePNPMv9DirectDependencyUsesLockfileResolution(t *testing.T) {
	assertDirectDependencyUsesLockfileResolution(t, "./pnpmv9_direct_resolution")
}
