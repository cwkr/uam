package clients

import (
	"database/sql"
	"errors"
	"github.com/blockloop/scan/v2"
	"github.com/cwkr/auth-server/internal/maputil"
	"log"
)

type sqlStore struct {
	inMemoryClientStore
	dbconn   *sql.DB
	settings *StoreSettings
}

func NewSqlStore(clientMap map[string]Client, dbs map[string]*sql.DB, settings *StoreSettings) (Store, error) {
	if dbs[settings.URI] == nil {
		dbconn, err := sql.Open("postgres", settings.URI)
		if err != nil {
			return nil, err
		}
		dbs[settings.URI] = dbconn
	}
	return &sqlStore{
		inMemoryClientStore: maputil.LowerKeys(clientMap),
		dbconn:              dbs[settings.URI],
		settings:            settings,
	}, nil
}

func (s *sqlStore) Authenticate(clientID, clientSecret string) (*Client, error) {
	if client, err := s.inMemoryClientStore.Authenticate(clientID, clientSecret); err == nil {
		return client, nil
	}
	if client, err := s.Lookup(clientID); err != nil {
		return nil, err
	} else {
		return s.inMemoryClientStore.authenticate(client, clientSecret)
	}
}

func (s *sqlStore) Lookup(clientID string) (*Client, error) {
	if c, err := s.inMemoryClientStore.Lookup(clientID); err == nil {
		return c, nil
	}

	var client Client

	log.Printf("SQL: %s; -- %s", s.settings.Query, clientID)
	// SELECT COALESCE(redirect_uri_pattern, ''), COALESCE(secret_hash, ''), COALESCE(session_name, ''),
	// disable_implicit, enable_refresh_token_rotation FROM clients WHERE lower(client_id) = lower($1)
	if rows, err := s.dbconn.Query(s.settings.Query, clientID); err == nil {
		if err := scan.RowStrict(&client, rows); err != nil {
			log.Printf("!!! Scan client failed: %v", err)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrClientNotFound
			}
			return nil, err
		}
	} else {
		log.Printf("!!! Query for client failed: %v", err)
		return nil, err
	}
	log.Printf("%#v", client)
	return &client, nil
}

func (s *sqlStore) Ping() error {
	return s.dbconn.Ping()
}
