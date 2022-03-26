package fileutil

import (
	"errors"
	"os"
)

func FileExists(name string) bool {
	stat, err := os.Stat(name)
	if err == nil {
		return !stat.IsDir()
	}
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	return false
}
