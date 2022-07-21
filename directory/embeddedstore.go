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
	sessionName     string
	sessionLifetime int
}

func NewEmbeddedStore(sessionStore sessions.Store, users map[string]AuthenticPerson, sessionName string, sessionLifetime int) Store {
	var lowerCaseUsers = make(map[string]AuthenticPerson)
	for userID, authenticPerson := range users {
		lowerCaseUsers[strings.ToLower(userID)] = authenticPerson
	}
	return &embeddedStore{
		sessionStore:    sessionStore,
		users:           lowerCaseUsers,
		sessionName:     sessionName,
		sessionLifetime: sessionLifetime,
	}
}

func (e embeddedStore) Authenticate(userID, password string) (string, error) {
	var lowercaseUserID = strings.ToLower(userID)
	var authenticPerson, foundUser = e.users[strings.ToLower(lowercaseUserID)]

	if foundUser {
		if err := bcrypt.CompareHashAndPassword([]byte(authenticPerson.PasswordHash), []byte(password)); err != nil {
			log.Printf("Authenticate failed: %v", err)
		} else {
			return lowercaseUserID, nil
		}
	}

	return "", ErrAuthenticationFailed
}

func (e embeddedStore) IsActiveSession(r *http.Request) (string, bool) {
	var session, _ = e.sessionStore.Get(r, e.sessionName)

	var uid, sct = session.Values["uid"], session.Values["sct"]

	if uid != nil && sct != nil && time.Unix(sct.(int64), 0).Add(time.Duration(e.sessionLifetime)*time.Second).After(time.Now()) {
		return uid.(string), true
	}

	return "", false
}

func (e embeddedStore) AuthenticationTime(r *http.Request) (time.Time, time.Time) {
	var session, _ = e.sessionStore.Get(r, e.sessionName)
	if sct := session.Values["sct"]; sct != nil {
		var ctime = time.Unix(sct.(int64), 0)
		return ctime, ctime.Add(time.Duration(e.sessionLifetime) * time.Second)
	}
	return time.Time{}, time.Time{}
}

func (e embeddedStore) Lookup(userID string) (Person, error) {
	var authenticPerson, found = e.users[strings.ToLower(userID)]

	if found {
		return authenticPerson.Person, nil
	}

	return Person{}, ErrPersonNotFound
}
