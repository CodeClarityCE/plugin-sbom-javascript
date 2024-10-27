package schemas

// Bundled dependencies are not marked as such
// Peer dependencies are not marked as such
type YarnV1LockFilePackageData struct {
	Dependencies         map[string]string `yaml:"dependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	Version              string            `yaml:"version,omitempty"`
	// Name                 string            `yaml:"name,omitempty"`
	Integrity string `yaml:"integrity,omitempty"`
	Resolved  string `yaml:"resolved,omitempty"`
}

type YarnV1LockFile map[string]YarnV1LockFilePackageData
