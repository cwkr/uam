package trl

import (
	"database/sql"
	"errors"
	"github.com/blockloop/scan/v2"
	"log"
	"time"
)

type sqlStore struct {
	dbconn   *sql.DB
	settings *StoreSettings
}

func NewSqlStore(dbs map[string]*sql.DB, settings *StoreSettings) (Store, error) {
	if dbs[settings.URI] == nil {
		dbconn, err := sql.Open("postgres", settings.URI)
		if err != nil {
			return nil, err
		}
		dbs[settings.URI] = dbconn
	}
	return &sqlStore{
		dbconn:   dbs[settings.URI],
		settings: settings,
	}, nil
}

func (s *sqlStore) Put(tokenID string, expirationTime time.Time) error {
	log.Printf("SQL: %s; -- %s, %v", s.settings.Insert, tokenID, expirationTime)
	// INSERT INTO token_revocation_list (jti, exp) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING
	_, err := s.dbconn.Exec(s.settings.Insert, tokenID, expirationTime)
	return err
}

func (s *sqlStore) Lookup(tokenID string) (*RevokedToken, error) {
	var revokedToken RevokedToken

	log.Printf("SQL: %s; -- %s", s.settings.Query, tokenID)
	// SELECT rvt, exp FROM token_revocation_list WHERE jti = $1 and exp >= current_timestamp
	if rows, err := s.dbconn.Query(s.settings.Query, tokenID); err == nil {
		if err := scan.RowStrict(&revokedToken, rows); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}
			return nil, err
		}
	} else {
		log.Printf("!!! Query for token id failed: %v", err)
		return nil, err
	}
	return &revokedToken, nil
}

func (s *sqlStore) Ping() error {
	return s.dbconn.Ping()
}
