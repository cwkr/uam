package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/cwkr/auth-server/fileutil"
	"github.com/cwkr/auth-server/oauth2"
	"github.com/cwkr/auth-server/stringutil"
	"github.com/cwkr/auth-server/userstore"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"strings"
)

type User struct {
	userstore.User
	PasswordHash string `json:"password_hash"`
}

type Settings struct {
	Issuer              string          `json:"issuer"`
	Port                int             `json:"port"`
	Title               string          `json:"title"`
	Users               map[string]User `json:"users"`
	Key                 string          `json:"key"`
	Clients             oauth2.Clients  `json:"clients"`
	Claims              oauth2.Claims   `json:"claims"`
	Scopes              []string        `json:"scopes"`
	AccessTokenLifetime int             `json:"access_token_lifetime"`
	SessionSecret       string          `json:"session_secret"`
	SessionID           string          `json:"session_id"`
	rsaPrivateKey       *rsa.PrivateKey
}

func NewDefaultSettings() *Settings {
	return &Settings{
		Issuer: "http://localhost:1337/",
		Port:   1337,
		Title:  "Auth Server",
		Users: map[string]User{
			"user": {
				User: userstore.User{
					FirstName:  "First Name",
					LastName:   "Last Name",
					Email:      "email@example.org",
					Department: "Example",
				},
				PasswordHash: "$2a$12$yos0Nv/lfhjKjJ7CSmkCteSJRmzkirYwGFlBqeY4ss3o3nFSb5WDy",
			},
		},
		Clients: oauth2.Clients{
			"app": "https?:\\/\\/localhost(:\\d+)?\\/",
		},
		AccessTokenLifetime: 3600,
		Claims: oauth2.Claims{
			"givenName": "{{ .User.FirstName }}",
			"sn":        "{{ .User.LastName }}",
			"email":     "{{ .User.Email }}",
			"groups":    "{{ .Groups | join ',' }}",
			"username":  "{{ .UserID | upper }}",
		},
		Scopes:        []string{"profile", "email", "offline_access"},
		SessionID:     "ASESSION",
		SessionSecret: stringutil.RandomBytesString(32),
	}
}

func (s *Settings) LoadKey(initConfig bool) error {
	var err error
	if strings.HasPrefix(s.Key, "-----BEGIN RSA PRIVATE KEY-----") {
		block, _ := pem.Decode([]byte(s.Key))
		s.rsaPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	} else if s.Key == "" || !fileutil.FileExists(s.Key) {
		if !initConfig && s.Key != "" {
			return errors.New("Missing key")
		}
		s.rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		pubASN1 := x509.MarshalPKCS1PrivateKey(s.rsaPrivateKey)
		keyBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: pubASN1,
		})
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
		s.rsaPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s Settings) PrivateKey() *rsa.PrivateKey {
	return s.rsaPrivateKey
}

func (s Settings) PublicKey() *rsa.PublicKey {
	return &s.rsaPrivateKey.PublicKey
}

func (s Settings) Authenticate(userID, password string) (userstore.User, bool) {
	var user, foundUser = s.Users[userID]

	if foundUser {
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			log.Printf("Authenticate failed: %v", err)
		} else {
			return user.User, true
		}
	}

	return userstore.User{}, false
}
