package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
			first := plugin.Start(restoreFixture(t, fixture), uuid.UUID{})
			checkDeterministic(t, fixture, first)
			for wsName, ws := range first.WorkSpaces {
				checkEdges(t, wsName, ws)
			}
			checkReachable(t, fixture, first)
			for wsName, ws := range first.WorkSpaces {
				checkDevProd(t, wsName, ws)
			}
			if len(first.WorkSpaces) == 1 {
				checkNPMDevFlags(t, fixture, first.WorkSpaces["."])
			}
		})
	}
}

// fixtureDirs lists the test folders that hold a stored lockfile.
func fixtureDirs(t *testing.T) []string {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		for _, lock := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
			if _, err := os.Stat(filepath.Join(e.Name(), lock+fixtureSuffix)); e.IsDir() && err == nil {
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

// reach returns the packages reachable from starts, and those reached as a child.
func reach(ws sbom.WorkSpace, starts []sbom.WorkSpaceDependency) (map[string]bool, map[string]bool) {
	seen, child := map[string]bool{}, map[string]bool{}
	var queue []string
	for _, d := range starts {
		queue = append(queue, d.Name+"@"+d.Version)
	}
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		if seen[key] {
			continue
		}
		seen[key] = true
		at := strings.LastIndex(key, "@")
		for depName, depVersion := range ws.Dependencies[key[:at]][key[at+1:]].Dependencies {
			child[depName+"@"+depVersion] = true
			queue = append(queue, depName+"@"+depVersion)
		}
	}
	return seen, child
}

// checkDevProd checks each reached package is labelled by what reaches it.
func checkDevProd(t *testing.T, wsName string, ws sbom.WorkSpace) {
	dev, devChild := reach(ws, ws.Start.DevDependencies)
	prod, prodChild := reach(ws, ws.Start.Dependencies)
	direct := map[string]bool{}
	for _, d := range append(ws.Start.Dependencies, ws.Start.DevDependencies...) {
		direct[d.Name+"@"+d.Version] = true
	}
	for name, versions := range ws.Dependencies {
		for version, info := range versions {
			key := name + "@" + version
			if !dev[key] && !prod[key] {
				continue
			}
			if info.Dev != dev[key] || info.Prod != prod[key] {
				t.Errorf("workspace %q: %s has dev=%v prod=%v, want dev=%v prod=%v", wsName, key, info.Dev, info.Prod, dev[key], prod[key])
			}
			if info.Direct != direct[key] || info.Transitive != (devChild[key] || prodChild[key]) {
				t.Errorf("workspace %q: %s has direct=%v transitive=%v, want direct=%v transitive=%v", wsName, key, info.Direct, info.Transitive, direct[key], devChild[key] || prodChild[key])
			}
		}
	}
}

// checkNPMDevFlags checks the labels agree with an npm v2+ lockfile's dev flags.
func checkNPMDevFlags(t *testing.T, fixture string, ws sbom.WorkSpace) {
	data, err := os.ReadFile(filepath.Join(fixture, "package-lock.json"))
	if err != nil {
		return
	}
	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			Dev         bool   `json:"dev"`
			DevOptional bool   `json:"devOptional"`
			Link        bool   `json:"link"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.LockfileVersion < 2 {
		return
	}
	for path, pkg := range lock.Packages {
		if path == "" || pkg.Link {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
		}
		info, ok := ws.Dependencies[name][pkg.Version]
		if !ok || (!info.Dev && !info.Prod) {
			continue
		}
		wantProd := !pkg.Dev
		wantDev := pkg.Dev || pkg.DevOptional || info.Dev
		if info.Prod != wantProd || info.Dev != wantDev {
			t.Errorf("%s: %s@%s has dev=%v prod=%v, lockfile says dev=%v devOptional=%v", path, name, pkg.Version, info.Dev, info.Prod, pkg.Dev, pkg.DevOptional)
		}
	}
}
