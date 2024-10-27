package exceptions

import (
	exceptions "github.com/CodeClarityCE/utility-types/exceptions"
)

const (
	GENERIC_ERROR                               exceptions.ERROR_TYPE = "GenericException"
	SOURCE_CODE_DIR_DOES_NOT_EXIST_ERROR        exceptions.ERROR_TYPE = "SourceCodeDirDoesNotExistException"
	NO_LOCKFILE_OR_PACKAGE_MANIFEST_FOUND_ERROR exceptions.ERROR_TYPE = "NoLockFileOrPackageManifestFoundException"
	CORRESPONDING_LOCK_FILE_MISSING             exceptions.ERROR_TYPE = "CorrespondingLockFileMissing"
	PACKAGE_FILE_PARSING_ERROR                  exceptions.ERROR_TYPE = "PackageFileParsingException"
	LOCK_FILE_PARSING_ERROR                     exceptions.ERROR_TYPE = "LockFileParsingException"
)
