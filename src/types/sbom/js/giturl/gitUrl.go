package giturl

type ParsedGitUrl struct {
	Protocol     string     `json:"protocol"`
	Host         string     `json:"host"`
	Repo         string     `json:"repo"`
	User         string     `json:"user"`
	Project      string     `json:"project"`
	RepoFullPath string     `json:"repo_full_path"`
	Version      string     `json:"version"`
	HostType     GitUrlHost `json:"host_type"`
}

type GitUrlHost string

const (
	GITHUB            GitUrlHost = "GITHUB"
	GITLAB            GitUrlHost = ""
	UNKOWN_GIT_SERVER GitUrlHost = "UNKOWN_GIT_SERVER"
)
