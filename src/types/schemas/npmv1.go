package schemas

type NPMLockFileV1Dependency struct {
	Name         string
	Version      string                             `json:"version,omitempty"`
	Resolved     string                             `json:"resolved,omitempty"`
	Integrity    string                             `json:"integrity,omitempty"`
	Requires     map[string]string                  `json:"requires,omitempty"`
	Dependencies map[string]NPMLockFileV1Dependency `json:"dependencies,omitempty"`
	Optional     bool                               `json:"optional,omitempty"`
	Bundled      bool                               `json:"bundled,omitempty"`
	Dev          bool                               `json:"dev,omitempty"`
	Scoped       bool                               `json:"scoped,omitempty"`
}

type NPMLockFileV1 struct {
	Name            string                             `json:"name,omitempty"`
	Version         string                             `json:"version,omitempty"`
	LockfileVersion int                                `json:"lockfileVersion,omitempty"`
	Requires        bool                               `json:"requires,omitempty"`
	Dependencies    map[string]NPMLockFileV1Dependency `json:"dependencies,omitempty"`
}
