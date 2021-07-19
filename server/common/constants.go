package common

import (
	"os"
	"path/filepath"
)

const (
	AppVersion      = "v0.5"
	LogPath         = "data/state/log/"
	ConfigPath      = "data/state/config/"
	DbPath          = "data/state/db/"
	FtsPath         = "data/state/search/"
	CertPath        = "data/state/certs/"
	TmpPath         = "data/cache/tmp/"
	CookieNameAuth  = "auth"
	CookieNameProof = "proof"
	CookieNameAdmin = "admin"
	CookiePathAdmin = "/admin/api/"
	CookiePath      = "/api/"
	FileIndex       = "./data/public/index.html"
	FileAssets      = "./data/public/"
	UrlSetup        = "/admin/setup"
)

func init() {
	cd := GetCurrentDir()
	os.MkdirAll(filepath.Join(cd, LogPath), os.ModePerm)
	os.MkdirAll(filepath.Join(cd, FtsPath), os.ModePerm)
	os.MkdirAll(filepath.Join(cd, ConfigPath), os.ModePerm)
	os.RemoveAll(filepath.Join(cd, TmpPath))
	os.MkdirAll(filepath.Join(cd, TmpPath), os.ModePerm)
}

var (
	BuildRef                  string
	BuildDate                 string
	SecretKey                 string
	SecretKeyDerivateForProof string
	SecretKeyDerivateForAdmin string
	SecretKeyDerivateForUser  string
	SecretKeyDerivateForHash  string
)

// InitSecretDerivate Improve security by calculating derivative of the secret key to restrict the attack surface
// in the worst case scenario with one compromise secret key
func InitSecretDerivate(secret string) {
	SecretKey = secret
	SecretKeyDerivateForProof = Hash("PROOF_"+SecretKey, len(SecretKey))
	SecretKeyDerivateForAdmin = Hash("ADMIN_"+SecretKey, len(SecretKey))
	SecretKeyDerivateForUser = Hash("USER_"+SecretKey, len(SecretKey))
	SecretKeyDerivateForHash = Hash("HASH_"+SecretKey, len(SecretKey))
}
