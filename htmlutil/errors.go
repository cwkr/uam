package htmlutil

import (
	"fmt"
	"log"
	"net/http"
)

func Error(w http.ResponseWriter, error string, code int) {
	var statusText = http.StatusText(code)
	log.Printf("!!! %d %s - %s\n", code, statusText, error)
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintf(w, "<!DOCTYPE html><link rel=\"stylesheet\" href=\"style\"><h1>%d %s</h1><p>%s</p>", code, statusText, error)
}
