package filestash

import (
	"embed"
	"fmt"
	"github.com/bingoohuang/filestash/server/plugin/plg_starter_http"
	"github.com/gorilla/mux"
	"io/fs"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"

	. "github.com/bingoohuang/filestash/server/common"
	. "github.com/bingoohuang/filestash/server/ctrl"
	. "github.com/bingoohuang/filestash/server/middleware"
	_ "github.com/bingoohuang/filestash/server/plugin"
)

//go:embed dist/data/public
var PublicFS embed.FS

var AssetsFS, _ = fs.Sub(PublicFS, "dist/data/public")

func GetPrefix(r *mux.Router, p string, h http.HandlerFunc) {
	r.PathPrefix(p).Handler(h).Methods("GET")
}
func GET(r *mux.Router, p string, h http.HandlerFunc)    { r.HandleFunc(p, h).Methods("GET") }
func POST(r *mux.Router, p string, h http.HandlerFunc)   { r.HandleFunc(p, h).Methods("POST") }
func DELETE(r *mux.Router, p string, h http.HandlerFunc) { r.HandleFunc(p, h).Methods("DELETE") }

type AppConfig struct {
	Port int
}

func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		Log.Warning("openbrowser: %v", err)
	}
}

func (appConfig AppConfig) Init(a *App) {
	if appConfig.Port > 0 {
		port := plg_starter_http.Register(appConfig.Port)
		go openBrowser(fmt.Sprintf("http://127.0.0.1:%d", port))
	}

	var middlewares []Middleware
	r := mux.NewRouter()

	// API for Session
	session := r.PathPrefix("/api/session").Subrouter()
	middlewares = []Middleware{ApiHeaders, SecureHeaders, SecureAjax, SessionStart}
	GET(session, "", Chain(SessionGet, middlewares, *a))
	middlewares = []Middleware{ApiHeaders, SecureHeaders, SecureAjax, BodyParser}
	POST(session, "", Chain(SessionAuthenticate, middlewares, *a))
	middlewares = []Middleware{ApiHeaders, SecureHeaders, SecureAjax, SessionTry}
	DELETE(session, "", Chain(SessionLogout, middlewares, *a))
	middlewares = []Middleware{ApiHeaders, SecureHeaders, SecureAjax}
	GET(session, "/auth/{service}", Chain(SessionOAuthBackend, middlewares, *a))

	// API for admin
	middlewares = []Middleware{ApiHeaders, SecureAjax}
	admin := r.PathPrefix("/admin/api").Subrouter()
	GET(admin, "/session", Chain(AdminSessionGet, middlewares, *a))
	POST(admin, "/session", Chain(AdminSessionAuthenticate, middlewares, *a))
	middlewares = []Middleware{ApiHeaders, AdminOnly, SecureAjax}
	admin.HandleFunc("/config", Chain(PrivateConfigHandler, middlewares, *a)).Methods("GET")
	admin.HandleFunc("/config", Chain(PrivateConfigUpdateHandler, middlewares, *a)).Methods("POST")
	middlewares = []Middleware{IndexHeaders, AdminOnly, SecureAjax}
	admin.HandleFunc("/log", Chain(FetchLogHandler, middlewares, *a)).Methods("GET")

	// API for File management
	files := r.PathPrefix("/api/files").Subrouter()
	middlewares = []Middleware{ApiHeaders, SecureHeaders, SessionStart, LoggedInOnly}
	files.HandleFunc("/cat", Chain(FileCat, middlewares, *a)).Methods("GET", "HEAD")
	files.HandleFunc("/zip", Chain(FileDownloader, middlewares, *a)).Methods("GET")
	middlewares = []Middleware{ApiHeaders, SecureHeaders, SecureAjax, SessionStart, LoggedInOnly}
	files.HandleFunc("/cat", Chain(FileAccess, middlewares, *a)).Methods("OPTIONS")
	files.HandleFunc("/cat", Chain(FileSave, middlewares, *a)).Methods("POST")
	GET(files, "/ls", Chain(FileLs, middlewares, *a))
	files.HandleFunc("/mv", Chain(FileMv, middlewares, *a)).Methods("GET")
	files.HandleFunc("/rm", Chain(FileRm, middlewares, *a)).Methods("GET")
	files.HandleFunc("/mkdir", Chain(FileMkdir, middlewares, *a)).Methods("GET")
	files.HandleFunc("/touch", Chain(FileTouch, middlewares, *a)).Methods("GET")
	middlewares = []Middleware{ApiHeaders, SessionStart, LoggedInOnly}
	files.HandleFunc("/search", Chain(FileSearch, middlewares, *a)).Methods("GET")

	// API for exporter
	middlewares = []Middleware{ApiHeaders, SecureHeaders, RedirectSharedLoginIfNeeded, SessionStart, LoggedInOnly}
	r.PathPrefix("/api/export/{share}/{mtype0}/{mtype1}").Handler(Chain(FileExport, middlewares, *a))

	// API for Shared link
	share := r.PathPrefix("/api/share").Subrouter()
	middlewares = []Middleware{ApiHeaders, SecureHeaders, SecureAjax, SessionStart, LoggedInOnly}
	share.HandleFunc("", Chain(ShareList, middlewares, *a)).Methods("GET")
	middlewares = []Middleware{ApiHeaders, SecureHeaders, SecureAjax, BodyParser}
	share.HandleFunc("/{share}/proof", Chain(ShareVerifyProof, middlewares, *a)).Methods("POST")
	middlewares = []Middleware{ApiHeaders, SecureHeaders, SecureAjax, CanManageShare}
	share.HandleFunc("/{share}", Chain(ShareDelete, middlewares, *a)).Methods("DELETE")
	middlewares = []Middleware{ApiHeaders, SecureHeaders, SecureAjax, BodyParser, CanManageShare}
	share.HandleFunc("/{share}", Chain(ShareUpsert, middlewares, *a)).Methods("POST")

	// Webdav server / Shared Link
	middlewares = []Middleware{IndexHeaders, SecureHeaders}
	r.HandleFunc("/s/{share}", Chain(IndexHandler(FileIndex), middlewares, *a)).Methods("GET")
	middlewares = []Middleware{WebdavBlacklist, SessionStart}
	r.PathPrefix("/s/{share}").Handler(Chain(WebdavHandler, middlewares, *a))

	// Application Resources
	middlewares = []Middleware{ApiHeaders}
	r.HandleFunc("/api/config", Chain(PublicConfigHandler, middlewares, *a)).Methods("GET")
	r.HandleFunc("/api/backend", Chain(AdminBackend, middlewares, *a)).Methods("GET")
	middlewares = []Middleware{StaticHeaders}
	GetPrefix(r, "/assets", Chain(EmbedHandler(AssetsFS), middlewares, *a))
	GET(r, "/favicon.ico", Chain(EmbedChangePathHandler(AssetsFS, "/assets/logo/favicon.ico"), middlewares, *a))
	GET(r, "/sw_cache.js", Chain(EmbedChangePathHandler(AssetsFS, "/assets/worker//sw_cache.js"), middlewares, *a))

	// Other endpoints
	middlewares = []Middleware{ApiHeaders}
	POST(r, "/report", Chain(ReportHandler, middlewares, *a))
	middlewares = []Middleware{IndexHeaders}
	GET(r, "/about", Chain(AboutHandler, middlewares, *a))
	r.HandleFunc("/robots.txt", func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte(""))
	})
	r.HandleFunc("/.well-known/security.txt", Chain(WellKnownSecurityHandler, []Middleware{}, *a)).Methods("GET")
	r.HandleFunc("/healthz", Chain(HealthHandler, []Middleware{}, *a)).Methods("GET")
	r.HandleFunc("/custom.css", Chain(CustomCssHandler, []Middleware{}, *a)).Methods("GET")

	if os.Getenv("DEBUG") == "true" {
		initDebugRoutes(r)
	}
	initPluginsRoutes(r, a)

	GetPrefix(r, "/admin", Chain(EmbedChangePathHandler(AssetsFS, "/"), middlewares, *a))
	GetPrefix(r, "/", Chain(EmbedChangePathHandler(AssetsFS, "/"), middlewares, *a))

	// Routes are served via plugins to avoid getting stuck with plain HTTP. The idea is to
	// support many more protocols in the future: HTTPS, HTTP2, TOR or whatever that sounds
	// fancy I don't know much when this got written: IPFS, solid, ...
	Log.Info("Filestash %s starting", AppVersion)

	if len(Hooks.Get.Starter()) == 0 {
		Log.Warning("No starter plugin available")
		return
	}

	for _, obj := range Hooks.Get.Starter() {
		go obj(r)
	}
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
