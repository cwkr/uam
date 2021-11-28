package main

type JwtokerConfig struct {
	Issuer string `json:"issuer"`
	Port int `json:"port"`
	Username string `json:"username"`
	Key string `json:"key"`
	ClientID string `json:"client_id"`
	Claims map[string]interface{} `json:"claims"`
	Scopes []string `json:"scopes"`
	AccessTokenLifetime int `json:"access_token_lifetime"`
}
