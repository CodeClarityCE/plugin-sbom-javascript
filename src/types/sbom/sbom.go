package sbom

import "time"

type Results struct {
	Sbom         []Dependency              `json:"sbom,omitempty"`
	Tree         map[string]DependencyTree `json:"tree,omitempty"`
	AnalysisInfo AnalysisInfo              `json:"analysis_info,omitempty"`
}

type ImportPathsRep struct {
	Data         string           `json:"data"`
	Dependencies []ImportPathsRep `json:"dependencies"`
}

type Dependency struct {
	Name              string    `json:"name"`
	Version           string    `json:"version"`
	FilePath          string    `json:"file_path"`
	IsPackageManaged  bool      `json:"is_package_managed"`
	IsSelfManaged     bool      `json:"is_self_managed"`
	PackageManager    string    `json:"package_manager"`
	Description       string    `json:"description"`
	Deprecated        bool      `json:"deprecated"`
	DeprecatedMessage string    `json:"deprecated_message"`
	Outdated          bool      `json:"outdated"`
	OutdatedMessage   string    `json:"outdated_message"`
	Release           time.Time `json:"release"`
	Website           string    `json:"website"`
	Github            string    `json:"github"`

	// Dependency Tree
	Dependencies []Dependency `json:"dependencies,omitempty"`

	// License & Find grouped & SBOM
	ImportingTopLevelDependencies []string       `json:"importing_top_level_dependencies,omitempty"`
	ImportPaths                   [][]string     `json:"import_paths,omitempty"`
	ImportPathsStrings            []string       `json:"import_paths_strings,omitempty"`
	ImportPathsRep                ImportPathsRep `json:"import_paths_rep,omitempty"`
	IsTopLevel                    bool           `json:"is_top_level,omitempty"`
	DirectDependency              bool           `json:"direct_dependency,omitempty"`
	TransitiveDependency          bool           `json:"transitive_dependency,omitempty"`
}

type AnalysisInfo struct {
	Status            string        `json:"status"`
	Errors            []interface{} `json:"errors"`
	DirName           string        `json:"dir_name"`
	PackageManager    string        `json:"package_manager"`
	AnalysisStartTime string        `json:"analysis_start_time"`
	AnalysisEndTime   string        `json:"analysis_end_time"`
	AnalysisDeltaTime float64       `json:"analysis_delta_time"`
	DependenciesFound bool          `json:"dependencies_found"`
}

type DependencyTree struct {
	Name string `json:"name"`
	Key  string `json:"key"`
	// Version string

	Data Dependency `json:"_"`

	Children []DependencyTree `json:"dependencies"`
	Parents  []DependencyTree `json:"_"`
}
