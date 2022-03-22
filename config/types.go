package config

import (
	"golang.org/x/crypto/bcrypt"
	"log"
	"regexp"
)

type Clients map[string]string

func (c Clients) ClientsMatchingRedirectURI(uri string) []string {
	var matches = make([]string, 0, len(c))
	for client, redirectURIPattern := range c {
		if regexp.MustCompile(redirectURIPattern).MatchString(uri) {
			matches = append(matches, client)
			break
		}
	}
	return matches
}

type UserDetails map[string]map[string]interface{}

type Config struct {
	Issuer              string                 `json:"issuer"`
	Port                int                    `json:"port"`
	Users               map[string]string      `json:"users"`
	UserDetails         UserDetails            `json:"user_details"`
	Key                 string                 `json:"key"`
	Clients             Clients                `json:"clients"`
	Claims              map[string]interface{} `json:"claims"`
	Scopes              []string               `json:"scopes"`
	AccessTokenLifetime int                    `json:"access_token_lifetime"`
	SessionKey          string                 `json:"session_key"`
	SessionID           string                 `json:"session_id"`
}

func (c Config) Authenticate(userID, password string) (map[string]interface{}, bool) {
	var hash, foundUser = c.Users[userID]

	if foundUser {
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
			log.Printf("Authenticate failed: %v", err)
		} else {
			return c.Lookup(userID)
		}
	}

	return nil, false
}

func (c Config) Lookup(userID string) (map[string]interface{}, bool) {
	var _, foundUser = c.Users[userID]
	var userDetails, foundDetails = c.UserDetails[userID]
	return userDetails, foundUser || foundDetails
}
