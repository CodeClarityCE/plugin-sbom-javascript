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

// PNPMLockFileV9Importer lists the versions installed for one workspace.
type PNPMLockFileV9Importer struct {
	Dependencies         map[string]PNPMLockFileV9ImporterDependency `yaml:"dependencies,omitempty"`
	DevDependencies      map[string]PNPMLockFileV9ImporterDependency `yaml:"devDependencies,omitempty"`
	OptionalDependencies map[string]PNPMLockFileV9ImporterDependency `yaml:"optionalDependencies,omitempty"`
}

type PNPMLockFileV9ImporterDependency struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

type PNPMLockFileV9 struct {
	LockfileVersion string                              `yaml:"lockfileVersion,omitempty"`
	Settings        Settings                            `yaml:"settings,omitempty"`
	Importers       map[string]PNPMLockFileV9Importer   `yaml:"importers,omitempty"`
	Packages        map[string]PNPMLockFileV9Dependency `json:"packages,omitempty"`
	Snapshots       map[string]PNPMLockFileV9Dependency `json:"snapshots,omitempty"`
}
