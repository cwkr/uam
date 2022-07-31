package people

import (
	"net/http"
	"time"
)

type Store interface {
	Authenticate(userID, password string) (string, error)
	IsActiveSession(r *http.Request) (string, bool)
	AuthenticationTime(r *http.Request) (time.Time, time.Time)
	SaveSession(r *http.Request, w http.ResponseWriter, userID string, authTime time.Time) error
	Lookup(userID string) (*Person, error)
	Ping() error
}
