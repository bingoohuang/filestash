package model

import (
	"fmt"
	. "github.com/bingoohuang/filestash/server/common"
	_ "github.com/bingoohuang/filestash/server/model/backend"
	"strings"
)

func isAllowed(conn map[string]string) bool {
	// by default, a hacker could use filestash to establish connections outside of what's
	// define in the config file. We need to prevent this
	possibilities := make([]map[string]interface{}, 0)
	for _, d := range Config.Conn {
		if d["type"] != conn["type"] {
			continue
		}
		if val, ok := d["hostname"]; ok {
			if val != conn["hostname"] {
				continue
			}
		}
		if val, ok := d["path"]; ok {
			if val == nil {
				val = "/"
			}
			if configPath, ok := val.(string); !ok {
				continue
			} else if !strings.HasPrefix(conn["path"], configPath) {
				continue
			}
		}
		if val, ok := d["url"]; ok {
			if val != conn["url"] {
				continue
			}
		}
		possibilities = append(possibilities, d)
	}
	return len(possibilities) > 0
}

func NewBackend(ctx *App, conn map[string]string) (IBackend, error) {
	if !isAllowed(conn) {
		return Backend.Get(BackendNil), ErrNotAllowed
	}
	return Backend.Get(conn["type"]).Init(conn, ctx)
}

func GetHome(b IBackend, base string) (string, error) {
	home := "/"
	if obj, ok := b.(interface{ Home() (string, error) }); ok {
		tmp, err := obj.Home()
		if err != nil {
			return base, err
		}
		home = EnforceDirectory(tmp)
	} else if _, err := b.Ls(base); err != nil {
		return base, err
	}

	base = EnforceDirectory(base)
	if strings.HasPrefix(home, base) {
		return "/" + home[len(base):], nil
	}
	return "/", nil
}

func MapStringInterfaceToMapStringString(m map[string]interface{}) map[string]string {
	res := make(map[string]string)
	for k, v := range m {
		res[k] = fmt.Sprintf("%v", v)
		if res[k] == "<nil>" {
			res[k] = ""
		}
	}
	return res
}
