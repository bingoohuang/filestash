package main

import (
	"fmt"
	"github.com/gorilla/mux"
	. "github.com/mickael-kerjean/filestash/server/common"
	. "github.com/mickael-kerjean/filestash/server/ctrl"
	. "github.com/mickael-kerjean/filestash/server/middleware"
	_ "github.com/mickael-kerjean/filestash/server/plugin"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
)

func main() {
	app := App{}
	Init(&app)
}

func Init(a *App) {
	r := mux.NewRouter()

	// API for Session
	session := r.PathPrefix("/api/session").Subrouter()
	session.HandleFunc("", Chain(SessionGet, *a, ApiHeaders, SecureHeaders, SecureAjax, SessionStart)).Methods("GET")
	session.HandleFunc("", Chain(SessionAuthenticate, *a, ApiHeaders, SecureHeaders, SecureAjax, BodyParser)).Methods("POST")
	session.HandleFunc("", Chain(SessionLogout, *a, ApiHeaders, SecureHeaders, SecureAjax, SessionTry)).Methods("DELETE")
	session.HandleFunc("/auth/{service}", Chain(SessionOAuthBackend, *a, ApiHeaders, SecureHeaders, SecureAjax)).Methods("GET")

	// API for admin
	admin := r.PathPrefix("/admin/api").Subrouter()
	admin.HandleFunc("/session", Chain(AdminSessionGet, *a, ApiHeaders, SecureAjax)).Methods("GET")
	admin.HandleFunc("/session", Chain(AdminSessionAuthenticate, *a, ApiHeaders, SecureAjax)).Methods("POST")
	admin.HandleFunc("/config", Chain(PrivateConfigHandler, *a, ApiHeaders, AdminOnly, SecureAjax)).Methods("GET")
	admin.HandleFunc("/config", Chain(PrivateConfigUpdateHandler, *a, ApiHeaders, AdminOnly, SecureAjax)).Methods("POST")
	admin.HandleFunc("/log", Chain(FetchLogHandler, *a, IndexHeaders, AdminOnly, SecureAjax)).Methods("GET")

	// API for File management
	files := r.PathPrefix("/api/files").Subrouter()
	files.HandleFunc("/cat", Chain(FileCat, *a, ApiHeaders, SecureHeaders, SessionStart, LoggedInOnly)).Methods("GET", "HEAD")
	files.HandleFunc("/zip", Chain(FileDownloader, *a, ApiHeaders, SecureHeaders, SessionStart, LoggedInOnly)).Methods("GET")
	middlewares := []Middleware{ApiHeaders, SecureHeaders, SecureAjax, SessionStart, LoggedInOnly}
	files.HandleFunc("/cat", Chain(FileAccess, *a, middlewares...)).Methods("OPTIONS")
	files.HandleFunc("/cat", Chain(FileSave, *a, middlewares...)).Methods("POST")
	files.HandleFunc("/ls", Chain(FileLs, *a, middlewares...)).Methods("GET")
	files.HandleFunc("/mv", Chain(FileMv, *a, middlewares...)).Methods("GET")
	files.HandleFunc("/rm", Chain(FileRm, *a, middlewares...)).Methods("GET")
	files.HandleFunc("/mkdir", Chain(FileMkdir, *a, middlewares...)).Methods("GET")
	files.HandleFunc("/touch", Chain(FileTouch, *a, middlewares...)).Methods("GET")
	files.HandleFunc("/search", Chain(FileSearch, *a, ApiHeaders, SessionStart, LoggedInOnly)).Methods("GET")

	// API for exporter
	r.PathPrefix("/api/export/{share}/{mtype0}/{mtype1}").Handler(Chain(FileExport, *a, ApiHeaders, SecureHeaders, RedirectSharedLoginIfNeeded, SessionStart, LoggedInOnly))

	// API for Shared link
	share := r.PathPrefix("/api/share").Subrouter()
	share.HandleFunc("", Chain(ShareList, *a, ApiHeaders, SecureHeaders, SecureAjax, SessionStart, LoggedInOnly)).Methods("GET")
	share.HandleFunc("/{share}/proof", Chain(ShareVerifyProof, *a, ApiHeaders, SecureHeaders, SecureAjax, BodyParser)).Methods("POST")
	share.HandleFunc("/{share}", Chain(ShareDelete, *a, ApiHeaders, SecureHeaders, SecureAjax, CanManageShare)).Methods("DELETE")
	share.HandleFunc("/{share}", Chain(ShareUpsert, *a, ApiHeaders, SecureHeaders, SecureAjax, BodyParser, CanManageShare)).Methods("POST")

	// Webdav server / Shared Link
	r.HandleFunc("/s/{share}", Chain(IndexHandler(FileIndex), *a, IndexHeaders, SecureHeaders)).Methods("GET")
	r.PathPrefix("/s/{share}").Handler(Chain(WebdavHandler, *a, WebdavBlacklist, SessionStart))

	// Application Resources
	r.HandleFunc("/api/config", Chain(PublicConfigHandler, *a, ApiHeaders)).Methods("GET")
	r.HandleFunc("/api/backend", Chain(AdminBackend, *a, ApiHeaders)).Methods("GET")
	r.PathPrefix("/assets").Handler(Chain(StaticHandler(FileAssets), *a, StaticHeaders)).Methods("GET")
	r.HandleFunc("/favicon.ico", Chain(StaticHandler(FileAssets+"/assets/logo/"), *a, StaticHeaders)).Methods("GET")
	r.HandleFunc("/sw_cache.js", Chain(StaticHandler(FileAssets+"/assets/worker/"), *a, StaticHeaders)).Methods("GET")

	// Other endpoints
	r.HandleFunc("/report", Chain(ReportHandler, *a, ApiHeaders)).Methods("POST")
	r.HandleFunc("/about", Chain(AboutHandler, *a, IndexHeaders)).Methods("GET")
	r.HandleFunc("/robots.txt", func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte(""))
	})
	r.HandleFunc("/.well-known/security.txt", Chain(WellKnownSecurityHandler, *a)).Methods("GET")
	r.HandleFunc("/healthz", Chain(HealthHandler, *a)).Methods("GET")
	r.HandleFunc("/custom.css", Chain(CustomCssHandler, *a)).Methods("GET")

	if os.Getenv("DEBUG") == "true" {
		initDebugRoutes(r)
	}
	initPluginsRoutes(r, a)

	r.PathPrefix("/admin").Handler(Chain(IndexHandler(FileIndex), *a, IndexHeaders)).Methods("GET")
	r.PathPrefix("/").Handler(Chain(IndexHandler(FileIndex), *a, IndexHeaders)).Methods("GET")

	// Routes are served via plugins to avoid getting stuck with plain HTTP. The idea is to
	// support many more protocols in the future: HTTPS, HTTP2, TOR or whatever that sounds
	// fancy I don't know much when this got written: IPFS, solid, ...
	Log.Info("Filestash %s starting", AppVersion)
	for _, obj := range Hooks.Get.Starter() {
		go obj(r)
	}
	if len(Hooks.Get.Starter()) == 0 {
		Log.Warning("No starter plugin available")
		return
	}
	select {}
}

func initDebugRoutes(r *mux.Router) {
	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)
	r.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	r.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	r.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	r.Handle("/debug/pprof/block", pprof.Handler("block"))
	r.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	r.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	r.HandleFunc("/debug/free", func(w http.ResponseWriter, r *http.Request) {
		debug.FreeOSMemory()
		w.Write([]byte("DONE"))
	})
	bToMb := func(b uint64) string {
		return strconv.Itoa(int(b / 1024 / 1024))
	}
	r.HandleFunc("/debug/memory", func(w http.ResponseWriter, r *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		w.Write([]byte("<p style='font-family:monospace'>"))
		w.Write([]byte("Alloc      = " + bToMb(m.Alloc) + "MiB <br>"))
		w.Write([]byte("TotalAlloc = " + bToMb(m.TotalAlloc) + "MiB <br>"))
		w.Write([]byte("Sys        = " + bToMb(m.Sys) + "MiB <br>"))
		w.Write([]byte("NumGC      = " + strconv.Itoa(int(m.NumGC))))
		w.Write([]byte("</p>"))
	})
}

func initPluginsRoutes(r *mux.Router, a *App) {
	// Endpoints hanle by plugins
	for _, obj := range Hooks.Get.HttpEndpoint() {
		obj(r, a)
	}
	// frontoffice overrides: it is the mean by which plugin can interact with the frontoffice
	for _, obj := range Hooks.Get.FrontendOverrides() {
		r.HandleFunc(obj, func(res http.ResponseWriter, req *http.Request) {
			res.Header().Set("Content-Type", GetMimeType(req.URL.String()))
			res.Write([]byte(fmt.Sprintf("/* Default '%s' */", obj)))
		})
	}
	// map which file can be open with what application
	r.HandleFunc("/overrides/xdg-open.js", func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", GetMimeType(req.URL.String()))
		res.Write([]byte(`window.overrides["xdg-open"] = function(mime){`))
		openers := Hooks.Get.XDGOpen()
		for i := 0; i < len(openers); i++ {
			res.Write([]byte(openers[i]))
		}
		res.Write([]byte(`return null;}`))
	})
}
