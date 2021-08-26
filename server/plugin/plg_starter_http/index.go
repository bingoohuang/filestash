package plg_starter_http

import (
	"fmt"
	"github.com/bingoohuang/filestash/server/common"
	"github.com/bingoohuang/gg/pkg/netx/freeport"
	"github.com/gorilla/mux"
	"net/http"
	"time"
)

func Register(port int) int {
	port = freeport.PortStart(port)
	addr := fmt.Sprintf(":%d", port)

	common.Hooks.Register.Starter(func(r *mux.Router) {
		common.Log.Info("[http] starting ...")
		fmt.Printf("filestash listening on %s\n", addr)
		srv := &http.Server{Addr: addr, Handler: r}
		//go ensureAppHasBooted(fmt.Sprintf("http://127.0.0.1:%d/about", port), fmt.Sprintf("[http] listening on :%d", port))
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				common.Log.Error("error: %v", err)
				return
			}
		}()
	})

	return port
}

func ensureAppHasBooted(address string, message string) {
	i := 0
	for {
		if i > 10 {
			common.Log.Warning("[http] didn't boot")
			break
		}
		time.Sleep(250 * time.Millisecond)
		res, err := http.Get(address)
		if err != nil {
			i += 1
			continue
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			i += 1
			continue
		}
		common.Log.Info(message)
		break
	}
}
