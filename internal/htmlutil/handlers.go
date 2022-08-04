package htmlutil

import (
	"log"
	"net/http"
)

func NotFoundHandler(basePath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
		Error(w, basePath, "page not found", http.StatusNotFound)
	})
}
