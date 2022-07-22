package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/cwkr/auth-server/fileutil"
	"github.com/cwkr/auth-server/oauth2"
	"github.com/cwkr/auth-server/people"
	"github.com/cwkr/auth-server/stringutil"
	"os"
	"path/filepath"
	"strings"
)

type Settings struct {
	Issuer                 string                            `json:"issuer"`
	Port                   int                               `json:"port"`
	Title                  string                            `json:"title"`
	Users                  map[string]people.AuthenticPerson `json:"users"`
	Key                    string                            `json:"key"`
	AdditionalKeys         []string                          `json:"additional_keys,omitempty"`
	Clients                oauth2.Clients                    `json:"clients"`
	Scope                  string                            `json:"scope"`
	AccessTokenExtraClaims map[string]string                 `json:"access_token_extra_claims"`
	AccessTokenTTL         int                               `json:"access_token_ttl"`
	RefreshTokenTTL        int                               `json:"refresh_token_ttl"`
	IDTokenTTL             int                               `json:"id_token_ttl"`
	IDTokenExtraClaims     map[string]string                 `json:"id_token_extra_claims"`
	SessionSecret          string                            `json:"session_secret"`
	SessionName            string                            `json:"session_name"`
	SessionTTL             int                               `json:"session_ttl"`
	DisablePKCE            bool                              `json:"disable_pkce"`
	PeopleStore            *people.StoreSettings             `json:"people_store,omitempty"`
	DisablePeopleAPI       bool                              `json:"disable_people_api,omitempty"`
	rsaSigningKey          *rsa.PrivateKey
	rsaSigningKeyID        string
	rsaAdditionalKeys      map[string]*rsa.PublicKey
}

func NewDefaultSettings() *Settings {
	return &Settings{
		Issuer: "http://localhost:6080/",
		Port:   6080,
		Title:  "Auth Server",
		Users: map[string]people.AuthenticPerson{
			"user": {
				Person: people.Person{
					GivenName:  "First Name",
					FamilyName: "Last Name",
					Email:      "email@example.org",
					Groups:     []string{"users"},
				},
				PasswordHash: "$2a$12$yos0Nv/lfhjKjJ7CSmkCteSJRmzkirYwGFlBqeY4ss3o3nFSb5WDy",
			},
		},
		Clients: oauth2.Clients{
			"app": oauth2.Client{
				RedirectURIPattern: "https?:\\/\\/localhost(:\\d+)?\\/",
			},
		},
		AccessTokenTTL:  3_600,
		RefreshTokenTTL: 28_800,
		IDTokenTTL:      28_800,
		AccessTokenExtraClaims: map[string]string{
			"prn":   "$user_id",
			"email": "$email",
		},
		IDTokenExtraClaims: map[string]string{},
		Scope:              "profile email",
		SessionName:        "ASESSION",
		SessionSecret:      stringutil.RandomBytesString(32),
		SessionTTL:         28_800,
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
