package server

import (
	_ "embed"
	"fmt"
	"github.com/cwkr/auth-server/internal/httputil"
	"log"
	"net/http"
	"time"
)

//go:embed assets/water.css
var cssContent string

func StyleHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Content-Length", fmt.Sprint(len(cssContent)))
		httputil.Cache(w, 120*time.Hour)
		fmt.Fprint(w, cssContent)
	})
}
