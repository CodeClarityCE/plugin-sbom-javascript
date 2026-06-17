package types

import (
	"encoding/json"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
)

// WorkspacesField accepts the npm/yarn `workspaces` key in either supported
// shape: an array of path globs (`["packages/*"]`) or the object form
// (`{"packages": ["packages/*"], "nohoist": [...]}`). The previous `[]string`
// type failed to unmarshal the object form, rejecting whole monorepos.
type WorkspacesField []string

func (w *WorkspacesField) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*w = arr
		return nil
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(data, &obj); err == nil {
		*w = obj.Packages
		return nil
	}
	// Unknown shape — treat as no workspaces rather than failing the whole parse.
	*w = nil
	return nil
}

type PackageFile struct {
	Name                 string            `json:"name,omitempty"`
	Version              string            `json:"version,omitempty"`
	Description          string            `json:"description,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
	BundleDependencies   []string          `json:"bundleDependencies,omitempty"`
	BundledDependencies  []string          `json:"bundledDependencies,omitempty"`
	WorkSpaces           WorkspacesField   `json:"workspaces"`
}

type ProjectInformation struct {
	RelativeLockFilePath      string
	RelativePackagePath       string
	LockFile                  string
	PackageFile               string
	PackageFileData           PackageFile
	PackageManager            packageManager.PACKAGE_MANAGER
	WorkSpaces                map[string]string
	WorkSpacesPackageFileData map[string]PackageFile
}

type Versions struct {
	Requires     map[string]string // Contains the constraints for the dependencies
	Dependencies map[string]string // Contains the exact versions of the dependencies
	Optional     bool
	Bundled      bool
	Dev          bool
	Scoped       bool
}

type LockFileInformation struct {
	PackageManager  packageManager.PACKAGE_MANAGER
	LockFileVersion int
	Dependencies    map[string]map[string]Versions
}
