package sbom

import (
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
)

type ImportMap map[string][][]string

type SeverityDist struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
}

type PatchType string

const (
	FULL    PatchType = "FULL"
	PARTIAL PatchType = "PARTIAL"
	NONE    PatchType = "NONE"
)

type WorkSpace struct {
	Dependencies map[string]map[string]Versions `json:"dependencies"`
	Start        Start                          `json:"start"`
}

type Versions struct {
	Key          string
	Requires     map[string]string
	Dependencies map[string]string
	Optional     bool
	Bundled      bool
	Dev          bool
	Transitive   bool
	Licenses     []string
}

type Start struct {
	Dependencies    []WorkSpaceDependency `json:"dependencies"`
	DevDependencies []WorkSpaceDependency `json:"dev_dependencies"`
}

type WorkSpaceDependency struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Constraint string `json:"constraint"`
}

type Output struct {
	WorkSpaces   map[string]WorkSpace `json:"workspaces"`
	AnalysisInfo AnalysisInfo         `json:"analysis_info"`
}

type AnalysisInfo struct {
	Status           codeclarity.AnalysisStatus     `json:"status"`
	ProjectName      string                         `json:"project_name"`
	WorkingDirectory string                         `json:"working_directory"`
	PackageManager   packageManager.PACKAGE_MANAGER `json:"package_manager"`
	Time             Time                           `json:"time"`
	Errors           []exceptions.Error             `json:"errors"`
	Paths            Paths                          `json:"paths"`
	Workspaces       Workspaces                     `json:"workspaces"`
	Extra            Extra                          `json:"extra"`
}

type Extra struct {
	VersionSeperator    string `json:"version_seperator"`
	ImportPathSeperator string `json:"import_path_seperator"`
	LockFileVersion     int    `json:"lock_file_version"`
}

type Workspaces struct {
	DefaultWorkspaceName     string `json:"default_workspace_name"`
	SelfManagedWorkspaceName string `json:"self_managed_workspace_name"`
	WorkSpacesUsed           bool   `json:"work_spaces_used"`
}

type Paths struct {
	Lockfile             string            `json:"lock_file_path"`
	PackageFile          string            `json:"package_file_path"`
	WorkSpacePackageFile map[string]string `json:"work_space_package_file_paths"`
	RelativeLockFile     string            `json:"relative_lock_file_path"`
	RelativePackageFile  string            `json:"relative_package_file_path"`
}

type Time struct {
	AnalysisStartTime string  `json:"analysis_start_time"`
	AnalysisEndTime   string  `json:"analysis_end_time"`
	AnalysisDeltaTime float64 `json:"analysis_delta_time"`
}

func ConvertSbomToMap(sbom Output) map[string]interface{} {
	sbomMap := make(map[string]interface{})
	sbomMap["workspaces"] = sbom.WorkSpaces
	sbomMap["analysis_info"] = sbom.AnalysisInfo
	return sbomMap
}
