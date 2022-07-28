package server

import (
	"encoding/json"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/people"
	"log"
	"net/http"
)

type healthHandler struct {
	peopleStore people.Store
}

func (i *healthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	var status = struct {
		Status string `json:"status"`
	}{"UP"}

	httputil.NoCache(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := i.peopleStore.Ping(); err != nil {
		log.Printf("%s %s", r.Method, r.URL)
		log.Printf("!!! 503 Service Unavailable - %s", err.Error())
		status.Status = err.Error()
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	var bytes, _ = json.Marshal(status)
	w.Write(bytes)
}

func HealthHandler(peopleStore people.Store) http.Handler {
	return &healthHandler{
		peopleStore: peopleStore,
	}
}
