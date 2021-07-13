package ssl

import (
	. "github.com/mickael-kerjean/filestash/server/common"
	"os"
	"path/filepath"
)

var keyPEMPath = filepath.Join(GetCurrentDir(), CertPath, "key.pem")
var certPEMPath = filepath.Join(GetCurrentDir(), CertPath, "cert.pem")

func init() {
	os.MkdirAll(filepath.Join(GetCurrentDir(), CertPath), os.ModePerm)
}

func Clear() {
	clearPrivateKey()
	clearCert()
}
