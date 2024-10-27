package lockfile

type YarnLockFileVersion string

const (
	YarnV1 YarnLockFileVersion = "YarnV1"
	YarnV2 YarnLockFileVersion = "YarnV2"
	YarnV3 YarnLockFileVersion = "YarnV3"
)

type NPMLockFileVersion string

const (
	NPMV1 NPMLockFileVersion = "NPMV1"
	NPMV2 NPMLockFileVersion = "NPMV2"
	NPMV3 NPMLockFileVersion = "NPMV3"
)
