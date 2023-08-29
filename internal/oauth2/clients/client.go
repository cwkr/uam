package clients

type Client struct {
	RedirectURIPattern         string `json:"redirect_uri_pattern,omitempty" db:"redirect_uri_pattern"`
	SecretHash                 string `json:"secret_hash,omitempty" db:"secret_hash"`
	SessionName                string `json:"session_name,omitempty" db:"session_name"`
	DisableImplicit            bool   `json:"disable_implicit,omitempty" db:"disable_implicit"`
	EnableRefreshTokenRotation bool   `json:"enable_refresh_token_rotation,omitempty" db:"enable_refresh_token_rotation"`
}
