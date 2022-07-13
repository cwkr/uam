package store

import (
	"net/http"
	"time"
)

type Authenticator interface {
	Authenticate(userID, password string) (User, bool)
	IsAuthenticated(r *http.Request) (string, User, bool)
	AuthenticationTime(r *http.Request) (time.Time, time.Time)
	Lookup(userID string) (User, bool)
}
