package people

import "errors"

var (
	ErrAuthenticationFailed = errors.New("invalid username and/or password")
	ErrPersonNotFound       = errors.New("person not found in store")
	ErrReadOnly             = errors.New("store is read-only")
)
