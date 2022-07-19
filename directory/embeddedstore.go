package directory

import (
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"time"
)

type AuthenticPerson struct {
	Person
	PasswordHash string `json:"password_hash"`
}

type embeddedStore struct {
	sessionStore    sessions.Store
	users           map[string]AuthenticPerson
	sessionID       string
	sessionLifetime int
}

func NewEmbeddedStore(sessionStore sessions.Store, users map[string]AuthenticPerson, sessionID string, sessionLifetime int) Store {
	var lowerCaseUsers = make(map[string]AuthenticPerson)
	for userID, authenticPerson := range users {
		lowerCaseUsers[strings.ToLower(userID)] = authenticPerson
	}
	return &embeddedStore{
		sessionStore:    sessionStore,
		users:           lowerCaseUsers,
		sessionID:       sessionID,
		sessionLifetime: sessionLifetime,
	}
}

func (e embeddedStore) Authenticate(userID, password string) (string, bool) {
	var lowercaseUserID = strings.ToLower(userID)
	var authenticPerson, foundUser = e.users[strings.ToLower(lowercaseUserID)]

	if foundUser {
		if err := bcrypt.CompareHashAndPassword([]byte(authenticPerson.PasswordHash), []byte(password)); err != nil {
			log.Printf("Authenticate failed: %v", err)
		} else {
			return lowercaseUserID, true
		}
	}

	return "", false
}

func (e embeddedStore) IsAuthenticated(r *http.Request) (string, bool) {
	var session, _ = e.sessionStore.Get(r, e.sessionID)

	var uid, sct = session.Values["uid"], session.Values["sct"]

	if uid != nil && sct != nil && time.Unix(sct.(int64), 0).Add(time.Duration(e.sessionLifetime)*time.Second).After(time.Now()) {
		return uid.(string), true
	}

	return "", false
}

func (e embeddedStore) AuthenticationTime(r *http.Request) (time.Time, time.Time) {
	var session, _ = e.sessionStore.Get(r, e.sessionID)
	if sct := session.Values["sct"]; sct != nil {
		var ctime = time.Unix(sct.(int64), 0)
		return ctime, ctime.Add(time.Duration(e.sessionLifetime) * time.Second)
	}
	return time.Time{}, time.Time{}
}

func (e embeddedStore) Lookup(userID string) (Person, bool) {
	var authenticPerson, found = e.users[strings.ToLower(userID)]

	if found {
		return authenticPerson.Person, true
	}

	return Person{}, false
}
