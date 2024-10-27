package schemas

type NPMLockFileV2DependencyData struct {
	Name         string
	Version      string                                 `json:"version,omitempty"`
	Resolved     string                                 `json:"resolved,omitempty"`
	Integrity    string                                 `json:"integrity,omitempty"`
	Requires     map[string]string                      `json:"requires,omitempty"`
	Dependencies map[string]NPMLockFileV2DependencyData `json:"dependencies,omitempty"`
	Optional     bool                                   `json:"optional,omitempty"`
	Bundled      bool                                   `json:"bundled,omitempty"`
	Dev          bool                                   `json:"dev,omitempty"`
	Scoped       bool                                   `json:"scoped,omitempty"`
}

type NPMLockFileV2 struct {
	Name            string                                 `json:"name,omitempty"`
	Version         string                                 `json:"version,omitempty"`
	LockfileVersion int                                    `json:"lockfileVersion,omitempty"`
	Requires        bool                                   `json:"requires,omitempty"`
	Packages        map[string]NPMLockFileV2PackageData    `json:"packages,omitempty"`
	Dependencies    map[string]NPMLockFileV2DependencyData `json:"dependencies,omitempty"`
}

type NPMLockFileV2PackageData struct {
	Name                 string
	Key                  string
	Version              string            `json:"version,omitempty"`
	Resolved             string            `json:"resolved,omitempty"`
	Integrity            string            `json:"integrity,omitempty"`
	Requires             map[string]string `json:"requires,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	BundleDependencies   []string          `json:"bundleDependencies,omitempty"`
	BundledDependencies  []string          `json:"bundledDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
	Optional             bool              `json:"optional,omitempty"`
	InBundle             bool              `json:"inBundle,omitempty"`
	Dev                  bool              `json:"dev,omitempty"`
	Scoped               bool
}
