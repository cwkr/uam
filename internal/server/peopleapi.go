package server

import (
	"encoding/json"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/oauth2"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/cwkr/auth-server/internal/stringutil"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"strings"
)

const ErrorAccessDenied = "access_denied"

type peopleAPIHandler struct {
	peopleStore    people.Store
	customVersions map[string]map[string]string
}

func (p *peopleAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions, http.MethodPut}, true)

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
			oauth2.AddExtraClaims(claims, customVersion, oauth2.User{UserID: userID, Person: *person}, "")
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

func LookupPersonHandler(peopleStore people.Store, customVersions map[string]map[string]string) http.Handler {
	return &peopleAPIHandler{
		peopleStore:    peopleStore,
		customVersions: customVersions,
	}
}

func PutPersonHandler(peopleStore people.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)

		httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions, http.MethodPut}, true)

		var person people.Person

		if bytes, err := io.ReadAll(r.Body); err == nil {
			if err := json.Unmarshal(bytes, &person); err != nil {
				oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
			return
		}

		var userID = mux.Vars(r)["user_id"]

		if !strings.EqualFold(userID, r.Context().Value("user_id").(string)) {
			oauth2.Error(w, ErrorAccessDenied, "", http.StatusForbidden)
			return
		}

		if err := peopleStore.Put(userID, &person); err != nil {
			log.Printf("!!! Update failed: %v", err)
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

type PasswordChange struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func ChangePasswordHandler(peopleStore people.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)

		httputil.AllowCORS(w, r, []string{http.MethodOptions, http.MethodPut}, true)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		var passwordChange PasswordChange

		if bytes, err := io.ReadAll(r.Body); err == nil {
			if err := json.Unmarshal(bytes, &passwordChange); err != nil {
				oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
			return
		}

		var userID = mux.Vars(r)["user_id"]

		if !strings.EqualFold(userID, r.Context().Value("user_id").(string)) {
			oauth2.Error(w, ErrorAccessDenied, "", http.StatusForbidden)
			return
		}

		if stringutil.IsAnyEmpty(passwordChange.OldPassword, passwordChange.NewPassword) {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, "old_password and new_password are required", http.StatusBadRequest)
			return
		}

		if _, err := peopleStore.Authenticate(userID, passwordChange.OldPassword); err != nil {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, "", http.StatusBadRequest)
			return
		}

		if err := peopleStore.SetPassword(userID, passwordChange.NewPassword); err != nil {
			log.Printf("!!! Update failed: %v", err)
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}
