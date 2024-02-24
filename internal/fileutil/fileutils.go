package fileutil

import (
	"os"
	"path/filepath"
	"strings"
)

func FileExists(name string) bool {
	if stat, err := os.Stat(name); err == nil {
		return !stat.IsDir()
	}
	return false
}

func ProbeSettingsFilename(cmdLineArg string) string {
	if cmdLineArg != "" {
		return cmdLineArg
	}
	var basename = filepath.Base(os.Args[0])
	var exeName = strings.TrimSuffix(basename, filepath.Ext(basename))
	var nameVariants = []string{exeName + ".jsonc", exeName + ".json"}
	for _, name := range nameVariants {
		if FileExists(name) {
			return name
		}
	}
	return exeName + ".jsonc"
}
