# Auth Server

This is a simple OAuth2 authorization server implementation supporting *Implicit*,
*Authorization Code* (with and without *PKCE*) and *Refresh Token* grant types.

It is possible to use a PostgreSQL database or LDAP as backend.

## Settings

```jsonc
{
  "issuer": "http://localhost:6080/",
  "port": 6080,
  "title": "Auth Server",
  "users": {
    "user": {
      "details": {
        "first_name": "First Name",
        "last_name": "Last Name"
      },
      "groups": [
        "admin"
      ],
      "password_hash": "$2a$12$yos0Nv/lfhjKjJ7CSmkCteSJRmzkirYwGFlBqeY4ss3o3nFSb5WDy"
    }
  },
  "key": "mykey.pem",
  // extra RSA public key to include in jwks
  "additional_keys": null,
  "clients": {
    "app": {
      "redirect_uri_pattern": "https?:\\/\\/localhost(:\\d+)?\\/"
    }
  },
  "claims": {
    "email": "{{ .Details.email }}",
    "givenName": "{{ .Details.first_name }}",
    "groups": "{{ .Groups | join ',' }}",
    "sn": "{{ .Details.last_name }}",
    "user_id": "{{ .UserID | upper }}",
    "prn": "{{ .UserID | lower }}"
  },
  // available scopes
  "scope": "profile email offline_access",
  "access_token_lifetime": 3600,
  "refresh_token_lifetime": 28800,
  "session_secret": "eoxxj3S-KsA7rlVHYfhOy22rW7abWDi5lS7WoCZ9hf4",
  "session_id": "ASESSION",
  "session_lifetime": 28800,
  "disable_pkce": false,
  "directory": {
    "uri": "postgresql://authserver:trustno1@localhost/dev?sslmode=disable",
    "credentials_query": "SELECT id, password_hash FROM users WHERE lower(id) = lower($1)",
    "groups_query": "SELECT id FROM groups WHERE lower(user_id) = lower($1)",
    "details_query": "SELECT first_name, last_name FROM users WHERE lower(id) = lower($1)"
  },
  "disable_people_lookup": false,
  "people_lookup_response": {
    "email": "{{ .Details.email }}",
    "givenName": "{{ .Details.first_name }}",
    "groups": "{{ .Groups | join ',' }}",
    "sn": "{{ .Details.last_name }}"
  }
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
