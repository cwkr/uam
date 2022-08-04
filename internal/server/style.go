package server

import (
	_ "embed"
	"fmt"
	"github.com/cwkr/auth-server/internal/httputil"
	"net/http"
	"time"
)

//go:embed assets/water.css
var cssContent string

func StyleHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.Cache(w, 120*time.Hour)
		fmt.Fprint(w, cssContent)
	})
}
