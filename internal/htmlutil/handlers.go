package htmlutil

import (
	"log"
	"net/http"
)

func NotFoundHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
		Error(w, "page not found", http.StatusNotFound)
	})
}
