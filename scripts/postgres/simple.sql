CREATE TABLE people
(
    user_id VARCHAR NOT NULL PRIMARY KEY,
    password_hash VARCHAR NOT NULL,
    groups VARCHAR ARRAY,
    given_name VARCHAR,
    family_name VARCHAR,
    email VARCHAR,
    birthdate DATE,
    department VARCHAR,
    phone_number VARCHAR,
    street_address VARCHAR,
    locality VARCHAR,
    postal_code VARCHAR,
    created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_modified TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TABLE clients
(
    client_id VARCHAR NOT NULL PRIMARY KEY,
    redirect_uri_pattern VARCHAR,
    secret_hash VARCHAR,
    session_name VARCHAR,
    disable_implicit BOOLEAN NOT NULL DEFAULT FALSE,
    enable_refresh_token_rotation BOOLEAN NOT NULL DEFAULT FALSE,
    created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_modified TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TABLE token_revocation_list
(
    jti VARCHAR PRIMARY KEY,
    rvt TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    exp TIMESTAMP WITH TIME ZONE NOT NULL
);
