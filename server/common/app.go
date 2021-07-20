package common

import "github.com/gorilla/mux"

type App struct {
	Backend    IBackend
	Body       map[string]interface{}
	Session    map[string]string
	Share      Share
	LogEnabled bool
	R          *mux.Router
}
