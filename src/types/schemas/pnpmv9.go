package schemas

type PNPMLockFileV9Dependency struct {
	Dependencies map[string]string `yaml:"dependencies,omitempty"`
	// Optional dependencies, and whether this package is optional (snapshots only).
	OptionalDependencies map[string]string `yaml:"optionalDependencies,omitempty"`
	Optional             bool              `yaml:"optional,omitempty"`
	PeerDependencies     map[string]string `yaml:"peerDependencies"`
	// TODO add PeerDependenciesMeta
	// TODO add transitivePeerDependencies
	Version string
	Engines map[string]string `yaml:"engines"`
}

type Settings struct {
	AutoInstallPeers         bool `yaml:"autoInstallPeers"`
	ExcludeLinksFromLockfile bool `yaml:"excludeLinksFromLockfile"`
}

type PNPMLockFileV9 struct {
	LockfileVersion string                              `yaml:"lockfileVersion,omitempty"`
	Settings        Settings                            `yaml:"settings,omitempty"`
	Packages        map[string]PNPMLockFileV9Dependency `json:"packages,omitempty"`
	Snapshots       map[string]PNPMLockFileV9Dependency `json:"snapshots,omitempty"`
}
