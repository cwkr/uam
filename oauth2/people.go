package oauth2

import (
	"encoding/json"
	"github.com/cwkr/auth-server/directory"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type peopleHandler struct {
	directoryStore     directory.Store
	responseProperties map[string]any
}

func (i *peopleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With")

	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var userID = mux.Vars(r)["user_id"]
	if person, err := i.directoryStore.Lookup(userID); err == nil {
		var responseData any = person

		if len(i.responseProperties) > 0 {
			responseData = map[string]any{}
			if err := customizeMap(responseData.(map[string]any), i.responseProperties, person); err != nil {
				Error(w, ErrorInternal, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		var bytes, err = json.Marshal(responseData)
		if err != nil {
			Error(w, ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	} else {
		if err == directory.ErrPersonNotFound {
			Error(w, ErrorNotFound, err.Error(), http.StatusNotFound)
		} else {
			Error(w, ErrorInternal, err.Error(), http.StatusInternalServerError)
		}
	}
}

func PeopleHandler(directoryStore directory.Store, responseProperties map[string]any) http.Handler {
	return &peopleHandler{
		directoryStore:     directoryStore,
		responseProperties: responseProperties,
	}
}
