package oauth2

import (
	"os"
	"strings"
)

const (
	ClaimClientID        = "client_id"
	ClaimExpirationTime  = "exp"
	ClaimIssuer          = "iss"
	ClaimIssuedAtTime    = "iat"
	ClaimNotBeforeTime   = "nbf"
	ClaimUserID          = "user_id"
	ClaimScope           = "scope"
	ClaimSubject         = "sub"
	ClaimType            = "typ"
	ClaimAudience        = "aud"
	ClaimAccessTokenHash = "at_hash"
)

func AddExtraClaims(claims map[string]any, extraClaims map[string]string, user User) {
	for key, tmpl := range extraClaims {
		if value := strings.TrimSpace(os.Expand(tmpl, func(name string) string {
			switch strings.ToLower(name) {
			case "user_id":
				return user.UserID
			case "birthdate":
				return user.Birthdate
			case "given_name":
				return user.GivenName
			case "family_name":
				return user.FamilyName
			case "email":
				return user.Email
			case "groups_semicolon":
				return strings.Join(user.Groups, ";")
			}
			return ""
		})); value != "" {
			claims[key] = value
		}
	}
}

func AddProfileClaims(claims map[string]any, user User) {
	if user.Birthdate != "" {
		claims["birthdate"] = user.Birthdate
	}
	if user.GivenName != "" {
		claims["given_name"] = user.GivenName
	}
	if user.FamilyName != "" {
		claims["family_name"] = user.FamilyName
	}
}

func AddEmailClaims(claims map[string]any, user User) {
	if user.Email != "" {
		claims["email"] = user.Email
		claims["email_verified"] = true
	}
}
