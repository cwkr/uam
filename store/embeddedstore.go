package store

import (
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"time"
)

type EmbeddedUser struct {
	User
	PasswordHash string `json:"password_hash"`
}

type embeddedAuthenticator struct {
	sessionStore    sessions.Store
	users           map[string]EmbeddedUser
	sessionID       string
	sessionLifetime int
}

func NewEmbeddedAuthenticator(sessionStore sessions.Store, users map[string]EmbeddedUser, sessionID string, sessionLifetime int) Authenticator {
	var lowerCaseUsers = make(map[string]EmbeddedUser)
	for userID, user := range users {
		lowerCaseUsers[strings.ToLower(userID)] = user
	}
	return &embeddedAuthenticator{
		sessionStore:    sessionStore,
		users:           lowerCaseUsers,
		sessionID:       sessionID,
		sessionLifetime: sessionLifetime,
	}
}

func (e embeddedAuthenticator) Authenticate(userID, password string) (User, bool) {
	var user, foundUser = e.users[strings.ToLower(userID)]

	if foundUser {
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			log.Printf("Authenticate failed: %v", err)
		} else {
			return user.User, true
		}
	}

	return User{}, false
}

func (e embeddedAuthenticator) IsAuthenticated(r *http.Request) (string, User, bool) {
	var session, _ = e.sessionStore.Get(r, e.sessionID)

	var usr, uid, sct = session.Values["usr"], session.Values["uid"], session.Values["sct"]

	if usr != nil && uid != nil && sct != nil && (sct.(time.Time)).Add(time.Duration(e.sessionLifetime)*time.Second).After(time.Now()) {
		return uid.(string), usr.(User), true
	}

	return "", User{}, false
}

func (e embeddedAuthenticator) AuthenticationTime(r *http.Request) (time.Time, time.Time) {
	var session, _ = e.sessionStore.Get(r, e.sessionID)
	if sct := session.Values["sct"]; sct != nil {
		var ctime = sct.(time.Time)
		return ctime, ctime.Add(time.Duration(e.sessionLifetime) * time.Second)
	}
	return time.Time{}, time.Time{}
}
