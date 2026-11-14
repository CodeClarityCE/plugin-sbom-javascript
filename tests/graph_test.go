package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	plugin "github.com/CodeClarityCE/plugin-sbom-javascript/src"
	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/google/uuid"
)

// Packages the fixture's own lockfile leaves unreachable.
var knownUnreachable = map[string]bool{
	// package.json lists "examples/*" but the folder is "exemples".
	"yarnv2/lodash.omit@4.5.0": true,
	// Decoy: its name must not satisfy a's optional react-native peer.
	"npmv3_peer_dependencies/other-react-native@1.0.0": true,
}

// TestGraphChecks runs every fixture and checks the SBOM graph, not just the status.
func TestGraphChecks(t *testing.T) {
	for _, fixture := range fixtureDirs(t) {
		t.Run(fixture, func(t *testing.T) {
			first := plugin.Start("./"+fixture, uuid.UUID{})
			checkDeterministic(t, fixture, first)
			for wsName, ws := range first.WorkSpaces {
				checkEdges(t, wsName, ws)
			}
			checkReachable(t, fixture, first)
		})
	}
}

// fixtureDirs lists the test folders that hold a lockfile.
func fixtureDirs(t *testing.T) []string {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		for _, lock := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
			if _, err := os.Stat(filepath.Join(e.Name(), lock)); e.IsDir() && err == nil {
				dirs = append(dirs, e.Name())
				break
			}
		}
	}
	if len(dirs) == 0 {
		t.Fatal("no fixtures found")
	}
	return dirs
}

func checkDeterministic(t *testing.T, fixture string, first sbom.Output) {
	want := graphJSON(t, first)
	for i := 0; i < 10; i++ {
		if got := graphJSON(t, plugin.Start("./"+fixture, uuid.UUID{})); got != want {
			t.Errorf("run %d gave a different SBOM than run 0", i+1)
			return
		}
	}
}

// graphJSON serialises the workspaces only; AnalysisInfo holds timestamps.
func graphJSON(t *testing.T, out sbom.Output) string {
	data, err := json.Marshal(out.WorkSpaces)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func checkEdges(t *testing.T, wsName string, ws sbom.WorkSpace) {
	for name, versions := range ws.Dependencies {
		for version, info := range versions {
			for depName, depVersion := range info.Dependencies {
				if _, ok := ws.Dependencies[depName][depVersion]; !ok {
					t.Errorf("workspace %q: %s@%s links to missing %s@%s", wsName, name, version, depName, depVersion)
				}
			}
		}
	}
}

// checkReachable checks every package is reachable from some workspace's dependencies.
// Workspaces share the lockfile's package map, so this is checked across all of them.
func checkReachable(t *testing.T, fixture string, out sbom.Output) {
	graph := map[string]map[string]string{}
	var queue []string
	for _, ws := range out.WorkSpaces {
		for name, versions := range ws.Dependencies {
			for version, info := range versions {
				graph[name+"@"+version] = info.Dependencies
			}
		}
		for _, d := range append(ws.Start.Dependencies, ws.Start.DevDependencies...) {
			queue = append(queue, d.Name+"@"+d.Version)
		}
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		deps, ok := graph[key]
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		for depName, depVersion := range deps {
			queue = append(queue, depName+"@"+depVersion)
		}
	}
	var missing []string
	for key := range graph {
		if _, known := knownUnreachable[fixture+"/"+key]; !seen[key] && !known {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d packages unreachable from any workspace's dependencies, e.g. %v", len(missing), missing[:min(5, len(missing))])
	}
}
