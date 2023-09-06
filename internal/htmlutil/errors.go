package htmlutil

import (
	"fmt"
	"log"
	"net/http"
)

func Error(w http.ResponseWriter, basePath, error string, code int) {
	var statusText = http.StatusText(code)
	log.Printf("!!! %d %s - %s", code, statusText, error)
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintf(w, "<!DOCTYPE html><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><link rel=\"stylesheet\" href=\"%s/style.css\"><h1>%d %s</h1><p>%s</p>", basePath, code, statusText, error)
}
