package ctrl

import (
	. "github.com/bingoohuang/filestash/server/common"
	"github.com/bingoohuang/filestash/server/model"
	"net/http"
	"strings"
)

func FileSearch(ctx App, res http.ResponseWriter, req *http.Request) {
	path, err := PathBuilder(ctx, req.URL.Query().Get("path"))
	if err != nil {
		path = "/"
	}
	q := req.URL.Query().Get("q")
	if !model.CanRead(&ctx) {
		SendErrorResult(res, ErrPermissionDenied)
		return
	}

	var searchResults []File
	if Config.Get("features.search.enable").Bool() {
		searchResults = model.SearchStateful(&ctx, path, q)
	} else {
		searchResults = model.SearchStateLess(&ctx, path, q)
	}

	if ctx.Session["path"] != "" {
		for i := 0; i < len(searchResults); i++ {
			searchResults[i].FPath = "/" + strings.TrimPrefix(
				searchResults[i].FPath,
				ctx.Session["path"],
			)
		}
	}
	SendSuccessResults(res, searchResults)
}
