package main

import (
	"github.com/bingoohuang/filestash"
	"github.com/bingoohuang/filestash/server/common"
	_ "github.com/bingoohuang/filestash/server/plugin"
)

func main() {
	app := common.App{}
	config := filestash.AppConfig{Port: 8334}
	if config.Init(&app).Start() {
		select {}
	}
}
