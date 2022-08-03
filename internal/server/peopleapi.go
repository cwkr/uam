package server

import (
	"encoding/json"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/oauth2"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type peopleAPIHandler struct {
	peopleStore    people.Store
	customVersions map[string]map[string]string
}

func (p *peopleAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions}, false)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var pathVars = mux.Vars(r)

	var userID = pathVars["user_id"]
	if person, err := p.peopleStore.Lookup(userID); err == nil {
		var bytes []byte
		var err error
		if customVersion, found := p.customVersions[pathVars["version"]]; found {
			var claims = make(map[string]any)
			oauth2.AddExtraClaims(claims, customVersion, oauth2.User{UserID: userID, Person: *person})
			bytes, err = json.Marshal(claims)
		} else if pathVars["version"] == "v1" {
			bytes, err = json.Marshal(person)
		} else {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, "unsupported version", http.StatusBadRequest)
			return
		}
		if err != nil {
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}

		httputil.NoCache(w)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(bytes)
	} else {
		if err == people.ErrPersonNotFound {
			oauth2.Error(w, oauth2.ErrorNotFound, err.Error(), http.StatusNotFound)
		} else {
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
		}
	}
}

func PeopleAPIHandler(peopleStore people.Store, customVersions map[string]map[string]string) http.Handler {
	return &peopleAPIHandler{
		peopleStore:    peopleStore,
		customVersions: customVersions,
	}
}
