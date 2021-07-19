package plugin

import (
	. "github.com/mickael-kerjean/filestash/server/common"
	_ "github.com/mickael-kerjean/filestash/server/plugin/plg_backend_backblaze"
	_ "github.com/mickael-kerjean/filestash/server/plugin/plg_backend_dav"
	_ "github.com/mickael-kerjean/filestash/server/plugin/plg_handler_console"
	_ "github.com/mickael-kerjean/filestash/server/plugin/plg_handler_syncthing"
	_ "github.com/mickael-kerjean/filestash/server/plugin/plg_security_svg"
)

func init() {
	Log.Debug("Plugin loader")
}
