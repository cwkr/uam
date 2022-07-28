package server

import (
	_ "embed"
	"net/http"
	"time"
)

//go:embed assets/favicon.ico
var favicon []byte

func FaviconHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
		var gmt, _ = time.LoadLocation("GMT")
		w.Header().Set("Expires", time.Now().Add(120*time.Hour).In(gmt).Format(time.RFC1123))
		w.Write(favicon)
	})
}
