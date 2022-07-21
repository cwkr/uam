package directory

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

func (p databaseStore) QueryGroups(userID string) ([]string, error) {
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

func (p databaseStore) QueryDetails(userID string) (map[string]any, error) {
	var details = make(map[string]any)

	log.Printf("SQL: %s; -- %s", p.settings.DetailsQuery, userID)
	// SELECT first_name, last_name FROM users WHERE lower(id) = lower($1)
	if rows, err := p.dbconn.Query(p.settings.DetailsQuery, userID); err == nil {
		var cols, _ = rows.Columns()
		if rows.Next() {
			var columns = make([]any, len(cols))
			var columnPointers = make([]any, len(cols))
			for i, _ := range columns {
				columnPointers[i] = &columns[i]
			}
			if err := rows.Scan(columnPointers...); err == nil {
				for i, colName := range cols {
					val := columnPointers[i].(*any)
					details[colName] = *val
				}
			} else {
				return nil, err
			}
		} else {
			return nil, ErrPersonNotFound
		}
	} else {
		return nil, err
	}
	return details, nil
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

func (p databaseStore) Lookup(userID string) (Person, error) {
	var person, err = p.embeddedStore.Lookup(userID)
	if err == nil {
		return person, nil
	}

	var details map[string]any
	var groups []string

	if details, err = p.QueryDetails(userID); err != nil {
		log.Printf("!!! Query for details failed: %v", err)
		return Person{}, err
	}

	if groups, err = p.QueryGroups(userID); err != nil {
		log.Printf("!!! Query for groups failed: %v", err)
		return Person{}, err
	}

	return Person{Groups: groups, Details: details}, nil
}
