package store

import (
	"database/sql"
	"errors"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
)

type postgresAuthenticator struct {
	embeddedAuthenticator
	dbconn       *sql.DB
	userQuery    string
	groupsQuery  string
	detailsQuery string
}

func NewPostgresAuthenticator(sessionStore sessions.Store, users map[string]EmbeddedUser, sessionID string, sessionLifetime int, uri, userQuery, groupsQuery, detailsQuery string) (Authenticator, error) {
	dbconn, err := sql.Open("postgres", uri)
	if err != nil {
		return nil, err
	}
	return &postgresAuthenticator{
		embeddedAuthenticator: embeddedAuthenticator{
			sessionStore:    sessionStore,
			users:           users,
			sessionID:       sessionID,
			sessionLifetime: sessionLifetime,
		},
		dbconn:       dbconn,
		userQuery:    userQuery,
		groupsQuery:  groupsQuery,
		detailsQuery: detailsQuery,
	}, nil
}

func (p postgresAuthenticator) QueryGroups(userID string) ([]string, error) {
	var groups []string

	log.Printf("SQL: %s; $1 = %s", p.groupsQuery, userID)
	// SELECT id FROM groups WHERE lower(user_id) = lower($1)
	if rows, err := p.dbconn.Query(p.groupsQuery, userID); err == nil {

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

func (p postgresAuthenticator) QueryDetails(userID string) (map[string]interface{}, error) {
	var details = make(map[string]interface{})

	log.Printf("SQL: %s; $1 = %s", p.detailsQuery, userID)
	// SELECT first_name, last_name FROM users WHERE lower(id) = lower($1)
	if rows, err := p.dbconn.Query(p.detailsQuery, userID); err == nil {
		var cols, _ = rows.Columns()
		if rows.Next() {
			var columns = make([]interface{}, len(cols))
			var columnPointers = make([]interface{}, len(cols))
			for i, _ := range columns {
				columnPointers[i] = &columns[i]
			}
			if err := rows.Scan(columnPointers...); err == nil {
				for i, colName := range cols {
					val := columnPointers[i].(*interface{})
					details[colName] = *val
				}
			} else {
				return nil, err
			}
		} else {
			return nil, errors.New("not found")
		}
	} else {
		return nil, err
	}
	return details, nil
}

func (p postgresAuthenticator) Authenticate(userID, password string) (string, bool) {
	var user, found = p.embeddedAuthenticator.Authenticate(userID, password)
	if found {
		return user, true
	}

	// SELECT id, password_hash FROM users WHERE lower(id) = lower($1)
	log.Printf("SQL: %s; $1 = %s", p.userQuery, userID)
	var row = p.dbconn.QueryRow(p.userQuery, userID)
	var passwordHash, realUserID string
	if err := row.Scan(&realUserID, &passwordHash); err == nil {
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			log.Printf("!!! Authenticate failed: %v", err)
		} else {
			return realUserID, true
		}
	} else {
		log.Printf("!!! Query for user failed: %v", err)
	}

	return "", false
}

func (p postgresAuthenticator) Lookup(userID string) (User, bool) {
	var user, found = p.embeddedAuthenticator.Lookup(userID)
	if found {
		return user, true
	}

	var details map[string]interface{}
	var groups []string
	var err error

	if details, err = p.QueryDetails(userID); err != nil {
		log.Printf("!!! Query for details failed: %v", err)
		return User{}, false
	}

	if groups, err = p.QueryGroups(userID); err != nil {
		log.Printf("!!! Query for groups failed: %v", err)
	}

	return User{Groups: groups, Details: details}, true
}
