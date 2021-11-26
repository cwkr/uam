package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
)

func Auth(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC().Unix()

	claims := map[string]interface{}{
		"sub": config.Username,
		"prn": config.Username,
		"iat": now,
		"nbf": now,
		"exp": now + 3600,
		"iss": fmt.Sprintf("http://localhost:%d/", config.Port),
	}

	for key, value := range config.Claims {
		claims[key] = value
	}

	x, _ := jwt.Signed(signer).Claims(claims).CompactSerialize()

	redirectUris := r.URL.Query()["redirect_uri"]
	states := r.URL.Query()["state"]

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

	if len(redirectUris) == 0 || len(states) == 0 {
		w.Header().Set("Content-Type", "application/json")
		response, _ := json.Marshal(
			map[string]interface{}{
				"access_token": x,
				"token_type": "bearer",
				"expires_in": 3600,
			},
		)
		w.Write(response)
	} else {
		http.Redirect(w, r, fmt.Sprintf("%s#access_token=%s&token_type=Bearer&expires_in=3600&state=%s", redirectUris[0], url.QueryEscape(x), url.QueryEscape(states[0])), 302)
	}
}
