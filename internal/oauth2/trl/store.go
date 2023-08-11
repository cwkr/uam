package trl

import (
	"time"
)

type RevokedToken struct {
	Type           string
	ExpirationTime time.Time
}

type Store interface {
	Put(tokenID, tokenType string, expirationTime time.Time) error
	Lookup(tokenID string) (*RevokedToken, error)
	Ping() error
}
