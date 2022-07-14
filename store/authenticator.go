package store

import (
	"net/http"
	"time"
)

type Authenticator interface {
	Authenticate(userID, password string) (string, bool)
	IsAuthenticated(r *http.Request) (string, bool)
	AuthenticationTime(r *http.Request) (time.Time, time.Time)
	Lookup(userID string) (User, bool)
}
