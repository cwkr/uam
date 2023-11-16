package server

import (
	"encoding/json"
	"github.com/cwkr/auth-server/internal/httputil"
	"net/http"
)

func InfoHandler(version, runtimeVersion string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var info = struct {
			Version   string `json:"version"`
			GoVersion string `json:"go_version"`
		}{version, runtimeVersion}

		httputil.NoCache(w)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		var bytes, _ = json.Marshal(info)
		w.Write(bytes)
	})
}
