package main

import (
	"github.com/bingoohuang/filestash"
	"github.com/bingoohuang/filestash/server/common"
	_ "github.com/bingoohuang/filestash/server/plugin"
	"github.com/gorilla/mux"
)

func main() {
	app := common.App{}
	config := filestash.AppConfig{
		Port:            8334,
		R:               mux.NewRouter(),
		AutoOpenBrowser: true,
	}

	config.Init(&app)
	if config.Start() {
		select {}
	}
}
