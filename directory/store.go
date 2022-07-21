package directory

import (
	"net/http"
	"time"
)

type Store interface {
	Authenticate(userID, password string) (string, error)
	IsAuthenticated(r *http.Request) (string, bool)
	AuthenticationTime(r *http.Request) (time.Time, time.Time)
	Lookup(userID string) (Person, bool)
}
