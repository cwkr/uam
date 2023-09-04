package clients

import (
	"github.com/cwkr/auth-server/internal/maputil"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

type inMemoryClientStore map[string]Client

func NewInMemoryClientStore(clientMap map[string]Client) Store {
	return inMemoryClientStore(maputil.LowerKeys(clientMap))
}

func (i inMemoryClientStore) authenticate(client *Client, clientSecret string) (*Client, error) {
	if clientSecret == "" {
		return nil, ErrClientSecretRequired
	}
	if client.SecretHash == "" {
		return nil, ErrClientNoSecret
	}
	if strings.HasPrefix(client.SecretHash, "$2") {
		if err := bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(clientSecret)); err != nil {
			return nil, err
		}
	} else {
		return nil, ErrClientInvalidSecretHash
	}
	return client, nil
}

func (i inMemoryClientStore) Authenticate(clientID, clientSecret string) (*Client, error) {
	if client, err := i.Lookup(clientID); err != nil {
		return nil, err
	} else {
		return i.authenticate(client, clientSecret)
	}
}

func (i inMemoryClientStore) Lookup(clientID string) (*Client, error) {
	if client, clientExists := i[strings.ToLower(clientID)]; clientExists {
		return &client, nil
	}
	return nil, ErrClientNotFound
}

func (i inMemoryClientStore) Ping() error {
	return nil
}
