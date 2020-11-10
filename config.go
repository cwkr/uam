package main

type JwtokerConfig struct {
	Port     int                    `json:"port,omitempty"`
	Username string                 `json:"username,omitempty"`
	Key      string                 `json:"key,omitempty"`
	Claims   map[string]interface{} `json:"claims,omitempty"`
}
