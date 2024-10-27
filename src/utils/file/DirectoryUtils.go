package file

import (
	"os"
)

func CheckDirExists(dirName string) bool {
	fileInfo, err := os.Stat(dirName)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return fileInfo.IsDir()
}
