package config

import (
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

type Config struct {
	Issuer              string                 `json:"issuer"`
	Port                int                    `json:"port"`
	Username            string                 `json:"username"`
	Key                 string                 `json:"key"`
	Clients             Clients                `json:"clients"`
	Claims              map[string]interface{} `json:"claims"`
	Scopes              []string               `json:"scopes"`
	AccessTokenLifetime int                    `json:"access_token_lifetime"`
}
