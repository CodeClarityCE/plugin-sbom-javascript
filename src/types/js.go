package types

import (
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
)

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
	WorkSpaces           []string          `json:"workspaces"`
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
