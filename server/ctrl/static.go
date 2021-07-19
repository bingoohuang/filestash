package ctrl

import (
	"fmt"
	"github.com/bingoohuang/gg/pkg/ss"
	. "github.com/bingoohuang/filestash/server/common"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"text/template"
)

func EmbedChangePathHandler(root fs.FS, changePath string) func(App, http.ResponseWriter, *http.Request) {
	return func(ctx App, w http.ResponseWriter, r *http.Request) {
		r.URL.Path = changePath
		http.FileServer(http.FS(root)).ServeHTTP(w, r)
	}
}
func EmbedHandler(root fs.FS) func(App, http.ResponseWriter, *http.Request) {
	return func(ctx App, w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.FS(root)).ServeHTTP(w, r)
	}
}
func StaticHandler(_path string) func(App, http.ResponseWriter, *http.Request) {
	return func(ctx App, res http.ResponseWriter, req *http.Request) {
		base := GetAbsolutePath(_path)
		srcPath := JoinPath(base, req.URL.Path)
		if srcPath == base {
			http.NotFound(res, req)
			return
		}
		ServeFile(res, req, srcPath)
	}
}

func IndexHandler(_path string) func(App, http.ResponseWriter, *http.Request) {
	return func(ctx App, res http.ResponseWriter, req *http.Request) {
		p := req.URL.Path

		/*if p != UrlSetup && ConfigAuthAdmin() == "" {
			http.Redirect(res, req, UrlSetup, http.StatusTemporaryRedirect)
			return
		} else */if !ss.AnyOf(p, "/", "/login", "/logout") && !ss.HasPrefix(p, "/s/", "/view/", "/files/", "/admin") {
			NotFoundHandler(ctx, res, req)
			return
		}
		ua := req.Header.Get("User-Agent")
		if ss.Contains(ua, "MSIE ", "Trident/", "Edge/") {
			// Microsoft is behaving on many occasion differently than Firefox / Chrome.
			// I have neither the time / motivation for it to work properly
			res.WriteHeader(http.StatusBadRequest)
			res.Write([]byte(
				Page(`
                  <h1>Internet explorer is not supported</h1>
                  <p>
                    We don't support IE / Edge at this time
                    <br>
                    Please use either Chromium, Firefox or Chrome
                  </p>
                `)))
			return
		}
		srcPath := GetAbsolutePath(_path)
		ServeFile(res, req, srcPath)
	}
}

func NotFoundHandler(_ App, res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(http.StatusNotFound)
	res.Write([]byte(Page(`<img style="max-width:800px" src="/assets/icons/404.svg" />`)))
}

func AboutHandler(_ App, res http.ResponseWriter, _ *http.Request) {
	t, _ := template.New("about").Parse(Page(`
	  <h1> {{index .App 0}} </h1>
	  <table>
		<tr> <td> Commit hash </td> <td> {{ index .App 1}} </td> </tr>
	  </table>
	  <style>
		table { margin: 0 auto; font-family: monospace; opacity: 0.8; }
		td { text-align: right; padding-left: 10px; }
	  </style>
	`))
	t.Execute(res, struct {
		App []string
	}{[]string{
		"Filestash " + AppVersion + "." + BuildDate,
		BuildRef,
	}})
}

func CustomCssHandler(_ App, res http.ResponseWriter, _ *http.Request) {
	res.Header().Set("Content-Type", "text/css")
	io.WriteString(res, Config.Get("general.custom_css").String())
}

func ServeFile(res http.ResponseWriter, req *http.Request, filePath string) {
	zFilePath := filePath + ".gz"
	bFilePath := filePath + ".br"

	etagNormal := hashFile(filePath, 10)
	etagGzip := hashFile(zFilePath, 10)
	etagBr := hashFile(bFilePath, 10)

	if req.Header.Get("If-None-Match") != "" {
		browserTag := req.Header.Get("If-None-Match")
		if browserTag == etagNormal {
			res.WriteHeader(http.StatusNotModified)
			return
		} else if browserTag == etagBr {
			res.WriteHeader(http.StatusNotModified)
			return
		} else if browserTag == etagGzip {
			res.WriteHeader(http.StatusNotModified)
			return
		}
	}
	head := res.Header()
	acceptEncoding := req.Header.Get("Accept-Encoding")
	if strings.Contains(acceptEncoding, "br") {
		if file, err := os.OpenFile(bFilePath, os.O_RDONLY, os.ModePerm); err == nil {
			head.Set("Content-Encoding", "br")
			head.Set("Etag", etagBr)
			io.Copy(res, file)
			file.Close()
			return
		}
	} else if strings.Contains(acceptEncoding, "gzip") {
		if file, err := os.OpenFile(zFilePath, os.O_RDONLY, os.ModePerm); err == nil {
			head.Set("Content-Encoding", "gzip")
			head.Set("Etag", etagGzip)
			io.Copy(res, file)
			file.Close()
			return
		}
	}

	file, err := os.OpenFile(filePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		http.NotFound(res, req)
		return
	}
	head.Set("Etag", etagNormal)
	io.Copy(res, file)
	file.Close()
}

func hashFile(path string, n int) string {
	f, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return ""
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return ""
	}
	return QuickHash(fmt.Sprintf("%s %d %d %s", path, stat.Size(), stat.Mode(), stat.ModTime()), n)
}

func hashFileContent(path string, n int) string {
	f, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return ""
	}
	defer f.Close()
	return HashStream(f, n)
}
