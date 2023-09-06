# Auth Server

This is a simple OAuth2 authorization server implementation supporting *Implicit*,
*Authorization Code* (with and without *PKCE*), *Refresh Token*, *Password* and
*Client Credentials* grant types.

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
  // extra public keys to include in jwks
  "additional_keys": null,
  "clients": {
    "app": {
      "redirect_uri_pattern": "https?:\\/\\/localhost(:\\d+)?\\/"
    }
  },
  "client_store": {
    "uri": "postgresql://authserver:trustno1@localhost/dev?sslmode=disable",
    "query": "SELECT COALESCE(redirect_uri_pattern, '') redirect_uri_pattern, COALESCE(secret_hash, '') secret_hash, COALESCE(session_name, '') session_name, disable_implicit, enable_refresh_token_rotation FROM clients WHERE lower(client_id) = lower($1)"
  },
  "access_token_extra_claims": {
    "prn": "$user_id",
    "email": "$email",
    "givenName": "$given_name",
    "groups": "$groups_semicolon_delimited",
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
    "credentials_query": "SELECT user_id, password_hash FROM users WHERE lower(user_id) = lower($1)",
    "groups_query": "SELECT UNNEST(groups) FROM users WHERE lower(user_id) = lower($1)",
    "details_query": "SELECT COALESCE(given_name, '') given_name, COALESCE(family_name, '') family_name, COALESCE(email, '') email, COALESCE(TO_CHAR(birthdate, 'YYYY-MM-DD'), '') birthdate, COALESCE(department, '') department, COALESCE(phone_number, '') phone_number, COALESCE(street_address, '') street_address, COALESCE(locality, '') locality, COALESCE(postal_code, '') postal_code FROM people WHERE lower(user_id) = lower($1)",
    "update": "UPDATE people SET given_name = $2, family_name = $3, email = $4, department = $5, birthdate = TO_DATE($6, 'YYYY-MM-DD'), phone_number = $7, locality = $8, street_address = $9, postal_code = $10, last_modified = now() WHERE lower(user_id) = lower($1)",
    "set_password": "UPDATE people SET password_hash = $2, last_modified = now() WHERE lower(user_id) = lower($1)"
  },
  "disable_api": false
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
    "groups": "$groups_semicolon_delimited",
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
      "department_attribute": "departmentnumber",
      "email_attribute": "mail",
      "family_name_attribute": "sn",
      "given_name_attribute": "givenname",
      "phone_number_attribute": "telephonenumber",
      "street_address_attribute": "street",
      "locality_attribute": "l",
      "postal_code_attribute": "postalcode"
    }
  },
  "disable_api": false
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
