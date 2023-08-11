package clients

import "errors"

var (
	ErrClientNotFound             = errors.New("client not found")
	ErrClientAuthenticationFailed = errors.New("client authentication failed")
	ErrClientInvalidSecretHash    = errors.New("invalid client secret hash")
	ErrClientNoSecret             = errors.New("client has no secret")
	ErrClientSecretRequired       = errors.New("client secret required")
)
