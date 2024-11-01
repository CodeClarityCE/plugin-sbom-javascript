package linkType

type LINK_TYPE string

const (
	GITHUB            LINK_TYPE = "GITHUB"
	GITLAB            LINK_TYPE = "GITLAB"
	UNKOWN_GIT_SERVER LINK_TYPE = "UNKOWN_GIT_SERVER"
	REMOTE_TARBALL    LINK_TYPE = "REMOTE_TARBALL"
	LOCAL_FILE        LINK_TYPE = "LOCAL_FILE"
	PACKAGE_MANAGED   LINK_TYPE = "PACKAGE_MANAGED"
	UNKNOWN_LINK_TYPE LINK_TYPE = "UNKNOWN"
	SELF_MANAGED      LINK_TYPE = "SELF_MANAGED"
)
