package main

import (
	"github.com/mickael-kerjean/filestash"
	"github.com/mickael-kerjean/filestash/server/common"
	_ "github.com/mickael-kerjean/filestash/server/plugin"
)

func main() {
	app := common.App{}

	filestash.AppConfig{Port: 8334}.Init(&app)
}
