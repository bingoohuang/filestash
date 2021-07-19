package common

import (
	"os"
	"path/filepath"
	"strings"
)

var MockCurrentDir string

func GetHomeDir() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".filestash")
}

func GetCurrentDir() string {
	if MockCurrentDir != "" {
		return MockCurrentDir
	}
	ex, _ := os.Getwd()
	return ex
}

func GetAbsolutePath(p string) string {
	return filepath.Join(GetCurrentDir(), p)
}

func IsDirectory(path string) bool {
	if path == "" {
		return false
	}
	if path[len(path)-1:] != "/" {
		return false
	}
	return true
}

// JoinPath joins 2 path together, result has a file
func JoinPath(base, file string) string {
	filePath := filepath.Join(base, file)
	if !strings.HasPrefix(filePath, base) {
		return base
	}
	return filePath
}

func EnforceDirectory(path string) string {
	if path == "" {
		return "/"
	} else if path[len(path)-1:] == "/" {
		return path
	}
	return path + "/"
}
