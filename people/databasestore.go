package people

import (
	"database/sql"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
)

type databaseStore struct {
	embeddedStore
	dbconn   *sql.DB
	settings *StoreSettings
}

func NewDatabaseStore(sessionStore sessions.Store, users map[string]AuthenticPerson, sessionName string, sessionLifetime int, settings *StoreSettings) (Store, error) {
	dbconn, err := sql.Open("postgres", settings.URI)
	if err != nil {
		return nil, err
	}
	return &databaseStore{
		embeddedStore: embeddedStore{
			sessionStore:    sessionStore,
			users:           users,
			sessionName:     sessionName,
			sessionLifetime: sessionLifetime,
		},
		dbconn:   dbconn,
		settings: settings,
	}, nil
}

func (p databaseStore) queryGroups(userID string) ([]string, error) {

	if p.settings.GroupsQuery == "" {
		return []string{}, nil
	}

	var groups []string

	log.Printf("SQL: %s; -- %s", p.settings.GroupsQuery, userID)
	// SELECT id FROM groups WHERE lower(user_id) = lower($1)
	if rows, err := p.dbconn.Query(p.settings.GroupsQuery, userID); err == nil {

		for rows.Next() {
			var group string
			if err := rows.Scan(&group); err == nil {
				groups = append(groups, group)
			} else {
				return nil, err
			}
		}

	} else {
		return nil, err
	}
	return groups, nil
}

func (p databaseStore) queryDetails(userID string) (*Person, error) {
	var person Person

	log.Printf("SQL: %s; -- %s", p.settings.DetailsQuery, userID)
	// SELECT given_name, family_name, email FROM users WHERE lower(id) = lower($1)
	if rows, err := p.dbconn.Query(p.settings.DetailsQuery, userID); err == nil {
		if rows.Next() {
			if err := rows.Scan(&person.GivenName, &person.FamilyName, &person.Email, &person.Birthdate); err != nil {
				return nil, err
			}
		} else {
			return nil, ErrPersonNotFound
		}
	} else {
		return nil, err
	}
	return &person, nil
}

func (p databaseStore) Authenticate(userID, password string) (string, error) {
	var realUserID, err = p.embeddedStore.Authenticate(userID, password)
	if err == nil {
		return realUserID, nil
	}

	// SELECT id, password_hash FROM users WHERE lower(id) = lower($1)
	log.Printf("SQL: %s; -- %s", p.settings.CredentialsQuery, userID)
	var row = p.dbconn.QueryRow(p.settings.CredentialsQuery, userID)
	var passwordHash string
	if err := row.Scan(&realUserID, &passwordHash); err == nil {
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			log.Printf("!!! Authenticate failed: %v", err)
		} else {
			return realUserID, nil
		}
	} else {
		log.Printf("!!! Query for person failed: %v", err)
		if err != sql.ErrNoRows {
			return "", err
		}
	}

	return "", ErrAuthenticationFailed
}

func (p databaseStore) Lookup(userID string) (*Person, error) {
	var person, err = p.embeddedStore.Lookup(userID)
	if err == nil {
		return person, nil
	}

	var groups []string

	if person, err = p.queryDetails(userID); err != nil {
		log.Printf("!!! Query for details failed: %v", err)
		return nil, err
	}

	if groups, err = p.queryGroups(userID); err != nil {
		log.Printf("!!! Query for groups failed: %v", err)
		return nil, err
	}
	person.Groups = groups

	return person, nil
}
