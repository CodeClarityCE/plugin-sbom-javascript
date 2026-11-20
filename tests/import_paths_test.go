package main

import (
	"encoding/json"
	"testing"

	plugin "github.com/CodeClarityCE/plugin-sbom-javascript/src"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// importInfo is the import path part of one dependency version, read from the JSON output.
type importInfo struct {
	IsTopLevel     bool       `json:"is_top_level"`
	TopLevel       []string   `json:"importing_top_level_dependencies"`
	ImportPaths    [][]string `json:"import_paths"`
	DevImportPaths [][]string `json:"dev_import_paths"`
}

// importInfoOf runs the plugin on a fixture and returns workspace -> "name@version" -> import info.
func importInfoOf(t *testing.T, fixture string) map[string]map[string]importInfo {
	t.Helper()
	out := plugin.Start(restoreFixture(t, fixture), uuid.UUID{})
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Workspaces map[string]struct {
			Dependencies map[string]map[string]importInfo `json:"dependencies"`
		} `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	result := map[string]map[string]importInfo{}
	for wsName, ws := range parsed.Workspaces {
		result[wsName] = map[string]importInfo{}
		for name, versions := range ws.Dependencies {
			for version, info := range versions {
				result[wsName][name+"@"+version] = info
			}
		}
	}
	return result
}

func TestImportPathsDirectDependencyIsItsOwnPath(t *testing.T) {
	deps := importInfoOf(t, "npmv3_shared_dev_prod")["."]

	assert.Equal(t, importInfo{
		IsTopLevel:     true,
		TopLevel:       []string{"app@1.0.0"},
		ImportPaths:    [][]string{{"app@1.0.0"}},
		DevImportPaths: [][]string{},
	}, deps["app@1.0.0"])
	assert.Equal(t, importInfo{
		IsTopLevel:     true,
		TopLevel:       []string{"tool@1.0.0"},
		ImportPaths:    [][]string{},
		DevImportPaths: [][]string{{"tool@1.0.0"}},
	}, deps["tool@1.0.0"])
}

func TestImportPathsTransitiveListsEveryTopLevelSplitByDevAndProd(t *testing.T) {
	deps := importInfoOf(t, "npmv3_shared_dev_prod")["."]

	assert.Equal(t, importInfo{
		IsTopLevel:     false,
		TopLevel:       []string{"app@1.0.0", "tool@1.0.0"},
		ImportPaths:    [][]string{{"app@1.0.0", "shared@1.0.0", "leaf@1.0.0"}},
		DevImportPaths: [][]string{{"tool@1.0.0", "shared@1.0.0", "leaf@1.0.0"}},
	}, deps["leaf@1.0.0"])
	assert.Equal(t, importInfo{
		IsTopLevel:     false,
		TopLevel:       []string{"tool@1.0.0"},
		ImportPaths:    [][]string{},
		DevImportPaths: [][]string{{"tool@1.0.0", "devonly@1.0.0"}},
	}, deps["devonly@1.0.0"])
}

func TestImportPathsStayWithinTheirWorkspace(t *testing.T) {
	workspaces := importInfoOf(t, "pnpmv9_workspace")

	root := workspaces["."]
	assert.Equal(t, [][]string{{"x@1.0.0"}}, root["x@1.0.0"].DevImportPaths)
	assert.Equal(t, importInfo{TopLevel: []string{}, ImportPaths: [][]string{}, DevImportPaths: [][]string{}}, root["y@1.0.0"])

	app := workspaces["packages/app"]
	assert.Equal(t, importInfo{
		IsTopLevel:     true,
		TopLevel:       []string{"y@1.0.0"},
		ImportPaths:    [][]string{{"y@1.0.0"}},
		DevImportPaths: [][]string{},
	}, app["y@1.0.0"])
	assert.Equal(t, importInfo{TopLevel: []string{}, ImportPaths: [][]string{}, DevImportPaths: [][]string{}}, app["x@1.0.0"])
}

// A cycle (a -> b -> a) must not loop, and the shortest path from each top-level wins.
func TestImportPathsShortestPathPerTopLevel(t *testing.T) {
	deps := importInfoOf(t, "npmv3_import_paths")["."]

	assert.Equal(t, [][]string{{"a@1.0.0", "d@1.0.0"}}, deps["d@1.0.0"].ImportPaths)
	assert.Equal(t, [][]string{{"a@1.0.0", "b@1.0.0"}}, deps["b@1.0.0"].ImportPaths)
	assert.Equal(t, [][]string{{"a@1.0.0"}}, deps["a@1.0.0"].ImportPaths)
}
