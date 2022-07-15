package store

import (
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/sessions"
	"log"
)

type directoryAuthenticator struct {
	embeddedAuthenticator
	ldapURL      string
	baseDN       string
	bindUser     string
	bindPassword string
	userQuery    string
	groupsQuery  string
	detailsQuery string
	details      []string
}

func NewDirectoryAuthenticator(sessionStore sessions.Store, users map[string]EmbeddedUser, sessionID string, sessionLifetime int, ldapURL, baseDN, bindUser, bindPassword, userQuery, groupsQuery, detailsQuery string, details []string) (Authenticator, error) {
	return &directoryAuthenticator{
		embeddedAuthenticator: embeddedAuthenticator{
			sessionStore:    sessionStore,
			users:           users,
			sessionID:       sessionID,
			sessionLifetime: sessionLifetime,
		},
		ldapURL:      ldapURL,
		baseDN:       baseDN,
		bindUser:     bindUser,
		bindPassword: bindPassword,
		userQuery:    userQuery,
		groupsQuery:  groupsQuery,
		detailsQuery: detailsQuery,
		details:      details,
	}, nil
}

func (p directoryAuthenticator) queryGroups(conn *ldap.Conn, userDN string) ([]string, error) {
	var groups []string

	log.Printf("LDAP: %s; %%s = %s", p.groupsQuery, userDN)
	// (&(objectClass=groupOfUniqueNames)(uniquemember=%s))
	var ldapGroupsSearch = ldap.NewSearchRequest(
		p.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(p.groupsQuery, ldap.EscapeFilter(userDN)),
		[]string{"dn", "cn"},
		nil,
	)
	if groupsResults, err := conn.Search(ldapGroupsSearch); err == nil {
		for _, group := range groupsResults.Entries {
			groups = append(groups, group.DN)
			//groups = append(groups, group.GetAttributeValue("cn"))
		}
	} else {
		return nil, err
	}

	return groups, nil
}

func (p directoryAuthenticator) queryDetails(conn *ldap.Conn, userID string) (string, map[string]any, error) {
	var details = make(map[string]any)
	var userDN string

	log.Printf("LDAP: %s; %%s = %s", p.detailsQuery, userID)
	// (&(objectClass=person)(uid=%s))
	var ldapSearch = ldap.NewSearchRequest(
		p.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(p.detailsQuery, userID),
		p.details,
		nil,
	)
	if results, err := conn.Search(ldapSearch); err == nil {
		if len(results.Entries) == 1 {
			var entry = results.Entries[0]
			userDN = entry.DN
			for _, key := range p.details {
				details[key] = entry.GetAttributeValue(key)
			}
		} else {
			return "", nil, errors.New("not found")
		}
	} else {
		return "", nil, err
	}

	return userDN, details, nil
}

func (p directoryAuthenticator) Authenticate(userID, password string) (string, bool) {
	var user, found = p.embeddedAuthenticator.Authenticate(userID, password)
	if found {
		return user, true
	}

	var conn, err = ldap.DialURL(p.ldapURL)
	if err != nil {
		log.Printf("!!! ldap connection error: %v", err)
		return "", false
	}
	defer conn.Close()

	if p.bindUser != "" && p.bindPassword != "" {
		if err = conn.Bind(p.bindUser, p.bindPassword); err != nil {
			log.Printf("!!! ldap bind error: %v", err)
			return "", false
		}
	}

	// (&(objectClass=person)(uid=%s))
	log.Printf("LDAP: %s; %%s = %s", p.userQuery, userID)
	var ldapSearch = ldap.NewSearchRequest(
		p.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(p.userQuery, ldap.EscapeFilter(userID)),
		[]string{"dn", "uid"},
		nil,
	)
	var results *ldap.SearchResult
	if results, err = conn.Search(ldapSearch); err == nil {
		if len(results.Entries) == 1 {
			var entry = results.Entries[0]
			if err = conn.Bind(entry.DN, password); err == nil {
				return entry.GetAttributeValue("uid"), true
			} else {
				log.Printf("!!! Authenticate failed: %v", err)
			}
		} else {
			log.Println("!!! User not found: " + userID)
			return "", false
		}
	} else {
		log.Println(err)
	}

	return "", false
}

func (p directoryAuthenticator) Lookup(userID string) (User, bool) {
	var user, found = p.embeddedAuthenticator.Lookup(userID)
	if found {
		return user, true
	}

	var details map[string]any
	var groups []string
	var err error
	var conn *ldap.Conn
	var userDN string

	conn, err = ldap.DialURL(p.ldapURL)
	if err != nil {
		log.Printf("!!! ldap connection error: %v", err)
		return User{}, false
	}
	defer conn.Close()

	if p.bindUser != "" && p.bindPassword != "" {
		if err = conn.Bind(p.bindUser, p.bindPassword); err != nil {
			log.Printf("!!! ldap bind error: %v", err)
			return User{}, false
		}
	}

	if userDN, details, err = p.queryDetails(conn, userID); err != nil {
		log.Printf("!!! Query for details failed: %v", err)
		return User{}, false
	}

	if groups, err = p.queryGroups(conn, userDN); err != nil {
		log.Printf("!!! Query for groups failed: %v", err)
	}

	return User{Groups: groups, Details: details}, true
}
