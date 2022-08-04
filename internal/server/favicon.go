package server

import (
	_ "embed"
	"github.com/cwkr/auth-server/internal/httputil"
	"net/http"
	"time"
)

//go:embed assets/favicon.ico
var favicon []byte

//go:embed assets/favicon-16x16.png
var favicon16x16 []byte

//go:embed assets/favicon-32x32.png
var favicon32x32 []byte

func FaviconHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
		httputil.Cache(w, 120*time.Hour)
		w.Write(favicon)
	})
}

func Favicon16x16Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		httputil.Cache(w, 120*time.Hour)
		w.Write(favicon16x16)
	})
}

func Favicon32x32Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		httputil.Cache(w, 120*time.Hour)
		w.Write(favicon32x32)
	})
}
