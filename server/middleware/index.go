package middleware

import (
	"bytes"
	"encoding/json"
	. "github.com/bingoohuang/filestash/server/common"
	"net/http"
	"sync"
	"time"
)

type Middleware func(func(App, http.ResponseWriter, *http.Request)) func(App, http.ResponseWriter, *http.Request)

func Chain(fn func(App, http.ResponseWriter, *http.Request), m []Middleware, app App) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		resw := NewResponseWriter(res)
		f := fn

		for i := len(m) - 1; i >= 0; i-- {
			f = m[i](f)
		}
		f(app, &resw, req)
		if req.Body != nil {
			req.Body.Close()
		}
		go Logger(app, &resw, req)
	}
}

type ResponseWriter struct {
	http.ResponseWriter
	status int
	start  time.Time
}

func NewResponseWriter(res http.ResponseWriter) ResponseWriter {
	return ResponseWriter{
		ResponseWriter: res,
		start:          time.Now(),
	}
}

func (w *ResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *ResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(b)
}

type LogEntry struct {
	Host       string  `json:"host"`
	Method     string  `json:"method"`
	RequestURI string  `json:"pathname"`
	Proto      string  `json:"proto"`
	Status     int     `json:"status"`
	Scheme     string  `json:"scheme"`
	UserAgent  string  `json:"userAgent"`
	Ip         string  `json:"ip"`
	Referer    string  `json:"referer"`
	Duration   float64 `json:"responseTime"`
	Version    string  `json:"version"`
	Backend    string  `json:"backend"`
}

func Logger(ctx App, res http.ResponseWriter, req *http.Request) {
	if obj, ok := res.(*ResponseWriter); ok && req.RequestURI != "/about" {
		point := LogEntry{
			Version:    AppVersion,
			Scheme:     req.URL.Scheme,
			Host:       req.Host,
			Method:     req.Method,
			RequestURI: req.RequestURI,
			Proto:      req.Proto,
			Status:     obj.status,
			UserAgent:  req.Header.Get("User-Agent"),
			Ip:         req.RemoteAddr,
			Referer:    req.Referer(),
			Duration:   float64(time.Now().Sub(obj.start)) / (1000 * 1000),
			Backend:    ctx.Session["type"],
		}
		if Config.Get("log.telemetry").Bool() {
			telemetry.Record(point)
		}
		if Config.Get("log.enable").Bool() {
			Log.Info("HTTP %3d %3s %6.1fms %s", point.Status, point.Method, point.Duration, point.RequestURI)
		}
	}
}

type Telemetry struct {
	Data []LogEntry
	mu   sync.Mutex
}

func (t *Telemetry) Record(point LogEntry) {
	t.mu.Lock()
	t.Data = append(t.Data, point)
	t.mu.Unlock()
}

func (t *Telemetry) Flush() {
	if len(t.Data) == 0 {
		return
	}
	t.mu.Lock()
	body, err := json.Marshal(t.Data)
	t.Data = t.Data[:0]
	t.mu.Unlock()

	if err != nil {
		return
	}
	r, err := http.NewRequest("POST", "https://downloads.filestash.app/event", bytes.NewReader(body))
	r.Header.Set("Connection", "Close")
	r.Header.Set("Content-Type", "application/json")
	r.Close = true
	if err != nil {
		return
	}
	resp, err := HTTP.Do(r)
	if err != nil {
		return
	}
	resp.Body.Close()
}

var telemetry = Telemetry{Data: make([]LogEntry, 0)}

func init() {
	go func() {
		for {
			time.Sleep(10 * time.Second)
			telemetry.Flush()
		}
	}()
}
