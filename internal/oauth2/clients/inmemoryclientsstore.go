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

func (i inMemoryClientStore) compareSecret(client *Client, clientSecret string) (*Client, error) {
	if clientSecret == "" {
		return nil, ErrClientSecretRequired
	}
	if client.SecretHash == "" {
		return nil, ErrClientNoSecret
	}
	// bcrypt hash or plaintext
	if strings.HasPrefix(client.SecretHash, "$2") {
		if err := bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(clientSecret)); err != nil {
			return nil, err
		}
	} else if clientSecret != client.SecretHash {
		return nil, ErrClientSecretMismatch
	}
	return client, nil
}

func (i inMemoryClientStore) Authenticate(clientID, clientSecret string) (*Client, error) {
	if client, err := i.Lookup(clientID); err != nil {
		return nil, err
	} else {
		return i.compareSecret(client, clientSecret)
	}
}

func (i inMemoryClientStore) Lookup(clientID string) (*Client, error) {
	if client, clientExists := i[strings.ToLower(clientID)]; clientExists {
		return &client, nil
	}
	return nil, ErrClientNotFound
}

func (i inMemoryClientStore) PerSessionNameMap(defaultSessionName string) (map[string][]string, error) {
	var clientsPerSessionName = map[string][]string{}
	for clientID, client := range i {
		if client.SessionName != "" {
			clientsPerSessionName[client.SessionName] = append(clientsPerSessionName[client.SessionName], clientID)
		} else if defaultSessionName != "" {
			clientsPerSessionName[defaultSessionName] = append(clientsPerSessionName[defaultSessionName], clientID)
		} else {
			return nil, ErrSessionNameMissing
		}
	}
	return clientsPerSessionName, nil
}

func (i inMemoryClientStore) Ping() error {
	return nil
}
