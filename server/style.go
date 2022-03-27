package server

import (
	_ "embed"
	"fmt"
	"net/http"
	"time"
)

//go:embed water.css
var cssContent string

func StyleHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		var gmt, _ = time.LoadLocation("GMT")
		w.Header().Set("Expires", time.Now().Add(120*time.Hour).In(gmt).Format(time.RFC1123))
		fmt.Fprint(w, cssContent)
	})
}
