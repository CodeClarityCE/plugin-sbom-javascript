package workspace

import (
	"sort"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/properties"
	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
)

type node struct{ name, version string }

func (n node) key() string { return n.name + properties.VERSION_SEPERATOR + n.version }

// fillImportPaths records, on every version, the top-level dependencies that install it
// and the shortest path from each, split into prod and dev paths.
func fillImportPaths(workspace sbomTypes.WorkSpace) sbomTypes.WorkSpace {
	for name, versions := range workspace.Dependencies {
		for version, info := range versions {
			info.IsTopLevel = false
			info.ImportingTopLevelDependencies = []string{}
			info.ImportPaths = [][]string{}
			info.DevImportPaths = [][]string{}
			workspace.Dependencies[name][version] = info
		}
	}

	type start struct {
		dep sbomTypes.WorkSpaceDependency
		dev bool
	}
	var starts []start
	for _, dep := range workspace.Start.Dependencies {
		starts = append(starts, start{dep, false})
	}
	for _, dep := range workspace.Start.DevDependencies {
		starts = append(starts, start{dep, true})
	}
	sort.SliceStable(starts, func(i, j int) bool {
		return starts[i].dep.Name+properties.VERSION_SEPERATOR+starts[i].dep.Version <
			starts[j].dep.Name+properties.VERSION_SEPERATOR+starts[j].dep.Version
	})

	for _, s := range starts {
		root := node{s.dep.Name, s.dep.Version}
		if _, ok := workspace.Dependencies[root.name][root.version]; !ok {
			continue
		}
		for target, path := range shortestPaths(workspace, root) {
			info := workspace.Dependencies[target.name][target.version]
			if target == root {
				info.IsTopLevel = true
			}
			if len(info.ImportingTopLevelDependencies) == 0 ||
				info.ImportingTopLevelDependencies[len(info.ImportingTopLevelDependencies)-1] != root.key() {
				info.ImportingTopLevelDependencies = append(info.ImportingTopLevelDependencies, root.key())
			}
			if s.dev {
				info.DevImportPaths = append(info.DevImportPaths, path)
			} else {
				info.ImportPaths = append(info.ImportPaths, path)
			}
			workspace.Dependencies[target.name][target.version] = info
		}
	}
	return workspace
}

// shortestPaths walks breadth first from root and returns one shortest path to every reachable version.
func shortestPaths(workspace sbomTypes.WorkSpace, root node) map[node][]string {
	paths := map[node][]string{root: {root.key()}}
	queue := []node{root}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		children := workspace.Dependencies[current.name][current.version].Dependencies
		names := make([]string, 0, len(children))
		for childName := range children {
			names = append(names, childName)
		}
		sort.Strings(names)
		for _, childName := range names {
			child := node{childName, children[childName]}
			if _, seen := paths[child]; seen {
				continue
			}
			if _, ok := workspace.Dependencies[child.name][child.version]; !ok {
				continue
			}
			path := append(append([]string{}, paths[current]...), child.key())
			paths[child] = path
			queue = append(queue, child)
		}
	}
	return paths
}
