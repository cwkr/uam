package people

import (
	"database/sql"
	"errors"
	"github.com/blockloop/scan/v2"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"strings"
)

type sqlStore struct {
	embeddedStore
	dbconn   *sql.DB
	settings *StoreSettings
}

func NewSqlStore(sessionStore sessions.Store, users map[string]AuthenticPerson, sessionTTL int64, dbs map[string]*sql.DB, settings *StoreSettings) (Store, error) {
	if dbs[settings.URI] == nil {
		dbconn, err := sql.Open("postgres", settings.URI)
		if err != nil {
			return nil, err
		}
		dbs[settings.URI] = dbconn
	}
	return &sqlStore{
		embeddedStore: embeddedStore{
			sessionStore: sessionStore,
			users:        users,
			sessionTTL:   sessionTTL,
		},
		dbconn:   dbs[settings.URI],
		settings: settings,
	}, nil
}

func (p sqlStore) queryGroups(userID string) ([]string, error) {

	if p.settings.GroupsQuery == "" {
		return []string{}, nil
	}

	var groups []string

	log.Printf("SQL: %s; -- %s", p.settings.GroupsQuery, userID)
	// SELECT id FROM groups WHERE lower(user_id) = lower($1)
	if rows, err := p.dbconn.Query(p.settings.GroupsQuery, userID); err == nil {
		if err := scan.Rows(&groups, rows); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	return groups, nil
}

func (p sqlStore) queryDetails(userID string) (*Person, error) {
	var person Person

	log.Printf("SQL: %s; -- %s", p.settings.DetailsQuery, userID)
	// SELECT COALESCE(given_name, '') given_name, COALESCE(family_name, '') family_name, COALESCE(email, '') email,
	// COALESCE(TO_CHAR(birthdate, 'YYYY-MM-DD'), '') birthdate, COALESCE(department, '') department,
	// COALESCE(phone_number, '') phone_number, COALESCE(street_address, '') street_address,
	// COALESCE(locality, '') locality, COALESCE(postal_code, '') postal_code
	// FROM people WHERE lower(user_id) = lower($1)
	if rows, err := p.dbconn.Query(p.settings.DetailsQuery, userID); err == nil {
		if err := scan.RowStrict(&person, rows); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrPersonNotFound
			}
			return nil, err
		}
	} else {
		return nil, err
	}
	return &person, nil
}

func (p sqlStore) Authenticate(userID, password string) (string, error) {
	var realUserID, err = p.embeddedStore.Authenticate(userID, password)
	if err == nil {
		return realUserID, nil
	}

	// SELECT user_id, password_hash FROM people WHERE lower(user_id) = lower($1)
	log.Printf("SQL: %s; -- %s", p.settings.CredentialsQuery, userID)
	var row = p.dbconn.QueryRow(p.settings.CredentialsQuery, userID)
	var passwordHash string
	if err := row.Scan(&realUserID, &passwordHash); err == nil {
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			log.Printf("!!! password comparison failed: %v", err)
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

func (p sqlStore) Lookup(userID string) (*Person, error) {
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

	log.Printf("%#v", *person)
	return person, nil
}

func (p sqlStore) Ping() error {
	return p.dbconn.Ping()
}

func (p sqlStore) ReadOnly() bool {
	return false
}

func (p sqlStore) Put(userID string, person *Person) error {
	// UPDATE people SET given_name = $2, family_name = $3, email = $4, department = $5,
	// birthdate = TO_DATE($6, 'YYYY-MM-DD'), phone_number = $7, locality = $8, street_address = $9, postal_code = $10,
	// last_modified = now() WHERE lower(user_id) = lower($1)
	log.Printf(
		"SQL: %s; -- %s, %s, %s, %s, %s, %s, %s, %s, %s, %s",
		p.settings.Update, userID, person.GivenName, person.FamilyName, person.Email, person.Department,
		person.Birthdate, person.PhoneNumber, person.StreetAddress, person.Locality, person.PostalCode,
	)
	if _, err := p.dbconn.Exec(
		p.settings.Update,
		userID,
		strings.TrimSpace(person.GivenName),
		strings.TrimSpace(person.FamilyName),
		strings.TrimSpace(person.Email),
		strings.TrimSpace(person.Department),
		strings.TrimSpace(person.Birthdate),
		strings.TrimSpace(person.PhoneNumber),
		strings.TrimSpace(person.StreetAddress),
		strings.TrimSpace(person.Locality),
		strings.TrimSpace(person.PostalCode),
	); err != nil {
		return err
	}
	return nil
}

func (p sqlStore) SetPassword(userID, password string) error {
	if passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 5); err != nil {
		return err
	} else {
		// UPDATE people SET password_hash = $2, last_modified = now() WHERE lower(user_id) = lower($1)
		log.Printf("SQL: %s; -- %s", p.settings.SetPassword, userID)
		if _, err := p.dbconn.Exec(p.settings.SetPassword, userID, passwordHash); err != nil {
			return err
		}
	}
	return nil
}
