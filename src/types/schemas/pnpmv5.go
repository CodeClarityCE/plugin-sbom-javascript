package schemas

// PNPMLockFileV5Package is a single entry in the `packages` map of a 5.x-family
// lockfile (pnpm 3-7). Unlike v9, the resolved dependency graph lives inside each
// package entry (`dependencies`/`optionalDependencies`), not in a separate
// `snapshots` block. Keys are of the form `/name/version` with an optional
// `_peer@x.y.z` peer-resolution suffix.
type PNPMLockFileV5Package struct {
	Dependencies         map[string]string `yaml:"dependencies,omitempty"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `yaml:"peerDependencies,omitempty"`
	Dev                  bool              `yaml:"dev,omitempty"`
	Optional             bool              `yaml:"optional,omitempty"`
	Engines              map[string]string `yaml:"engines,omitempty"`
}

type PNPMLockFileV5 struct {
	LockfileVersion string                           `yaml:"lockfileVersion,omitempty"`
	Packages        map[string]PNPMLockFileV5Package `yaml:"packages,omitempty"`
}
