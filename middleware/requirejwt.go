package middleware

import (
	"context"
	"fmt"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/oauth2"
	"net/http"
)

func RequireJWT(next http.Handler, tokenVerifier TokenVerifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var accessToken = httputil.ExtractAccessToken(r)
		if accessToken == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			oauth2.Error(w, "unauthorized", "authentication required", http.StatusUnauthorized)
			return
		}
		var userID, err = tokenVerifier.VerifyToken(accessToken)
		if err != nil {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer error=\"invalid_token\", error_description=\"%s\"", err.Error()))
			oauth2.Error(w, "invalid_token", err.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "user_id", userID)))
	})
}
