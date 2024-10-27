package schemas

import (
	linkType "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/linkType"
	versionType "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/versionType"
)

// Bundled dependencies are not supported in yarn v2+ (https://next.yarnpkg.com/getting-started/migration?ref=yarnpkg#dont-use-bundledependencies)
// They are installed as "normal" dependencies
type YarnV2LockFilePackageData struct {
	Dependencies         map[string]string           `yaml:"dependencies,omitempty"`
	DependenciesMeta     map[string]DependenciesMeta `yaml:"dependenciesMeta,omitempty"`
	PeerDependencies     map[string]string           `yaml:"peerDependencies,omitempty"`
	PeerDependenciesMeta map[string]DependenciesMeta `yaml:"peerDependenciesMeta,omitempty"`
	Version              string                      `yaml:"version,omitempty"`
	Name                 string                      `yaml:"name,omitempty"`
	Key                  string                      `yaml:"key,omitempty"`
	Checksum             string                      `yaml:"checksum,omitempty"`
	LanguageName         string                      `yaml:"languageName,omitempty"`
	Resolution           string                      `yaml:"resolution,omitempty"`
	LinkType             linkType.LINK_TYPE
	VersionType          versionType.VERSION_TYPE
}

type YarnV2LockFile map[string]YarnV2LockFilePackageData
