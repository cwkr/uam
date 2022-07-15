package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/cwkr/auth-server/fileutil"
	"github.com/cwkr/auth-server/oauth2"
	"github.com/cwkr/auth-server/store"
	"github.com/cwkr/auth-server/stringutil"
	"os"
	"path/filepath"
	"strings"
)

type Settings struct {
	Issuer               string                        `json:"issuer"`
	Port                 int                           `json:"port"`
	Title                string                        `json:"title"`
	Users                map[string]store.EmbeddedUser `json:"users"`
	Key                  string                        `json:"key"`
	AdditionalKeys       []string                      `json:"additional_keys"`
	Clients              oauth2.Clients                `json:"clients"`
	Claims               oauth2.Claims                 `json:"claims"`
	Scopes               []string                      `json:"scopes"`
	AccessTokenLifetime  int                           `json:"access_token_lifetime"`
	RefreshTokenLifetime int                           `json:"refresh_token_lifetime"`
	SessionSecret        string                        `json:"session_secret"`
	SessionID            string                        `json:"session_id"`
	SessionLifetime      int                           `json:"session_lifetime"`
	DisablePKCE          bool                          `json:"disable_pkce"`
	StoreURI             string                        `json:"store_uri,omitempty"`
	UserQuery            string                        `json:"user_query,omitempty"`
	GroupsQuery          string                        `json:"groups_query,omitempty"`
	DetailsQuery         string                        `json:"details_query,omitempty"`
	Details              []string                      `json:"details,omitempty"`
	rsaSigningKey        *rsa.PrivateKey
	rsaSigningKeyID      string
	rsaAdditionalKeys    map[string]*rsa.PublicKey
}

func NewDefaultSettings() *Settings {
	return &Settings{
		Issuer: "http://localhost:1337/",
		Port:   1337,
		Title:  "Auth Server",
		Users: map[string]store.EmbeddedUser{
			"user": {
				User: store.User{
					Details: map[string]any{
						"first_name": "First Name",
						"last_name":  "Last Name",
						"email":      "email@example.org",
					},
					Groups: []string{"users"},
				},
				PasswordHash: "$2a$12$yos0Nv/lfhjKjJ7CSmkCteSJRmzkirYwGFlBqeY4ss3o3nFSb5WDy",
			},
		},
		Clients: oauth2.Clients{
			"app": oauth2.Client{
				RedirectURIPattern: "https?:\\/\\/localhost(:\\d+)?\\/",
			},
		},
		AccessTokenLifetime:  3_600,
		RefreshTokenLifetime: 28_800,
		Claims: oauth2.Claims{
			"givenName": "{{ .Details.first_name }}",
			"sn":        "{{ .Details.last_name }}",
			"email":     "{{ .Details.email }}",
			"groups":    "{{ .Groups | join ',' }}",
			"user_id":   "{{ .UserID | upper }}",
		},
		Scopes:          []string{"profile", "email", "offline_access"},
		SessionID:       "ASESSION",
		SessionSecret:   stringutil.RandomBytesString(32),
		SessionLifetime: 28_800,
	}
}

func (s *Settings) LoadKeys(genNew bool) error {
	var err error
	s.rsaSigningKeyID = "sigkey"
	if strings.HasPrefix(s.Key, "-----BEGIN RSA PRIVATE KEY-----") {
		block, _ := pem.Decode([]byte(s.Key))
		s.rsaSigningKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	} else if s.Key == "" || !fileutil.FileExists(s.Key) {
		if !genNew && s.Key != "" {
			return errors.New("missing key")
		}
		var keyBytes []byte
		s.rsaSigningKey, keyBytes, err = oauth2.GeneratePrivateKey(2048)
		if err != nil {
			return err
		}

		if s.Key == "" {
			s.Key = string(keyBytes)
		} else {
			err := os.WriteFile(s.Key, keyBytes, 0600)
			if err != nil {
				return err
			}
		}
	} else {
		pemBytes, err := os.ReadFile(s.Key)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(pemBytes)
		s.rsaSigningKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		s.rsaSigningKeyID = strings.TrimSuffix(filepath.Base(s.Key), filepath.Ext(s.Key))
	}

	s.rsaAdditionalKeys, err = oauth2.LoadPublicKeys(s.AdditionalKeys)
	return err
}

func (s Settings) PrivateKey() *rsa.PrivateKey {
	return s.rsaSigningKey
}

func (s Settings) PublicKey() *rsa.PublicKey {
	return &s.rsaSigningKey.PublicKey
}

func (s Settings) KeyID() string {
	return s.rsaSigningKeyID
}

func (s Settings) AllKeys() map[string]*rsa.PublicKey {
	var allKeys = make(map[string]*rsa.PublicKey)
	allKeys[s.rsaSigningKeyID] = s.PublicKey()
	for kid, publicKey := range s.rsaAdditionalKeys {
		allKeys[kid] = publicKey
	}
	return allKeys
}
