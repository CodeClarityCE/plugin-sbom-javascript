package schemas

// Bundle dependencies are not supported in yarn v2+ (https://next.yarnpkg.com/getting-started/migration?ref=yarnpkg#dont-use-bundledependencies)
// They are installed as "normal" dependencies
type YarnV3LockFilePackageData struct {
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
}

type YarnV3LockFile map[string]YarnV3LockFilePackageData
