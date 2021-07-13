package common

import (
	"github.com/gorilla/mux"
	"io"
	"net/http"
)

type Plugin struct {
	Type   string
	Enable bool
}

type Register struct{}
type Get struct{}

var Hooks = struct {
	Get      Get
	Register Register
}{
	Get:      Get{},
	Register: Register{},
}

var process_file_content_before_send []func(io.ReadCloser, *App, *http.ResponseWriter, *http.Request) (io.ReadCloser, error)

func (r Register) ProcessFileContentBeforeSend(fn func(io.ReadCloser, *App, *http.ResponseWriter, *http.Request) (io.ReadCloser, error)) {
	process_file_content_before_send = append(process_file_content_before_send, fn)
}
func (g Get) ProcessFileContentBeforeSend() []func(io.ReadCloser, *App, *http.ResponseWriter, *http.Request) (io.ReadCloser, error) {
	return process_file_content_before_send
}

var http_endpoint []func(*mux.Router, *App) error

func (r Register) HttpEndpoint(fn func(*mux.Router, *App) error) {
	http_endpoint = append(http_endpoint, fn)
}
func (g Get) HttpEndpoint() []func(*mux.Router, *App) error {
	return http_endpoint
}

var starter_process []func(*mux.Router)

func (r Register) Starter(fn func(*mux.Router)) {
	starter_process = append(starter_process, fn)
}
func (g Get) Starter() []func(*mux.Router) {
	return starter_process
}

/*
 * UI Overrides
 * They are the means by which server plugin change the frontend behaviors.
 */
var overrides []string

func (r Register) FrontendOverrides(url string) {
	overrides = append(overrides, url)
}
func (g Get) FrontendOverrides() []string {
	return overrides
}

var xdgOpen []string

func (r Register) XDGOpen(jsString string) {
	xdgOpen = append(xdgOpen, jsString)
}
func (g Get) XDGOpen() []string {
	return xdgOpen
}

const OverrideVideoSourceMapper = "/overrides/video-transcoder.js"

func init() {
	Hooks.Register.FrontendOverrides(OverrideVideoSourceMapper)
}
