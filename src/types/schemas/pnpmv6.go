package schemas

// PNPMLockFileV6Package is a single entry in the `packages` map of a 6.x-family
// lockfile (pnpm 8). The per-package shape matches v5; only the package-key format
// differs (`/name@version(peer@x.y.z)` instead of `/name/version_peer@x.y.z`),
// which the resolver handles via cleanNameV6.
type PNPMLockFileV6Package struct {
	Dependencies         map[string]string `yaml:"dependencies,omitempty"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `yaml:"peerDependencies,omitempty"`
	Dev                  bool              `yaml:"dev,omitempty"`
	Optional             bool              `yaml:"optional,omitempty"`
	Engines              map[string]string `yaml:"engines,omitempty"`
}

type PNPMLockFileV6 struct {
	LockfileVersion string                           `yaml:"lockfileVersion,omitempty"`
	Packages        map[string]PNPMLockFileV6Package `yaml:"packages,omitempty"`
}
