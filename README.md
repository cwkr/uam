# Auth Server

This is a simple OAuth2 authorization server implementation supporting *Implicit*,
*Authorization Code* (with and without *PKCE*) and *Refresh Token* grant types.

It is possible to use a PostgreSQL database or LDAP as people store.

## Settings

### PostgreSQL as people store

```jsonc
{
  "issuer": "http://localhost:6080/",
  "port": 6080,
  "users": {
    "user": {
      "given_name": "First Name",
      "family_name": "Last Name",
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
  "access_token_extra_claims": {
    "prn": "$user_id",
    "email": "$email",
    "givenName": "$given_name",
    "groups": "$groups_semicolon",
    "sn": "$family_name",
    "user_id": "$user_id"
  },
  // available scopes
  "extra_scope": "profile email offline_access",
  "access_token_ttl": 3600,
  "refresh_token_ttl": 28800,
  "session_secret": "eoxxj3S-KsA7rlVHYfhOy22rW7abWDi5lS7WoCZ9hf4",
  "session_name": "ASESSION",
  "session_ttl": 28800,
  "people_store": {
    "uri": "postgresql://authserver:trustno1@localhost/dev?sslmode=disable",
    "credentials_query": "SELECT id, password_hash FROM users WHERE lower(id) = lower($1)",
    "groups_query": "SELECT id FROM groups WHERE lower(user_id) = lower($1)",
    "details_query": "SELECT first_name, last_name, email, TO_CHAR(birthdate, 'YYYY-MM-DD') FROM users WHERE lower(id) = lower($1)"
  },
  "disable_people_api": false
}
```

### Oracle Internt Directory (LDAP) as people store

```jsonc
{
  "issuer": "http://localhost:6080/",
  "port": 6080,
  "key": "mykey.pem",
  "clients": {
    "app": {
      "redirect_uri_pattern": "https?:\\/\\/localhost(:\\d+)?\\/"
    }
  },
  "access_token_extra_claims": {
    "prn": "$user_id",
    "email": "$email",
    "givenName": "$given_name",
    "groups": "$groups_semicolon",
    "sn": "$family_name",
    "user_id": "$user_id"
  },
  "extra_scope": "profile",
  "access_token_ttl": 3600,
  "refresh_token_ttl": 28800,
  "session_secret": "jpDc7ah68Vw8yOccr9yIaWDR7_oqN1vHrLQEJ1YLvnQ",
  "session_name": "ASESSION",
  "session_ttl": 28800,
  "people_store": {
    "uri": "ldaps://cn=access_user,cn=Users,dc=example,dc=org:trustno1@oid.example.org:3070",
    "credentials_query": "(&(objectClass=person)(uid=%s))",
    "groups_query": "(&(objectClass=groupOfUniqueNames)(uniquemember=%s))",
    "details_query": "(&(objectClass=person)(uid=%s))",
    "parameters": {
      "base_dn": "dc=example,dc=org",
      "user_id_attribute": "uid",
      "group_id_attribute": "dn",      
      "department_attribute": "department",
      "email_attribute": "mail",
      "family_name_attribute": "sn",
      "given_name_attribute": "givenname",
    }
  },
  "disable_people_api": false
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
