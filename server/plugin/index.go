package plugin

import (
	. "github.com/bingoohuang/filestash/server/common"
	_ "github.com/bingoohuang/filestash/server/plugin/plg_backend_backblaze"
	_ "github.com/bingoohuang/filestash/server/plugin/plg_backend_dav"
	_ "github.com/bingoohuang/filestash/server/plugin/plg_handler_console"
	_ "github.com/bingoohuang/filestash/server/plugin/plg_handler_syncthing"
	_ "github.com/bingoohuang/filestash/server/plugin/plg_security_svg"
)

func init() {
	Log.Debug("Plugin loader")
}
