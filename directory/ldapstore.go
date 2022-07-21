package directory

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/sessions"
	"log"
	"net/url"
	"strings"
)

type ldapStore struct {
	embeddedStore
	ldapURL           string
	baseDN            string
	bindUser          string
	bindPassword      string
	detailsAttributes []string
	userIDAttr        string
	groupIDAttr       string
	settings          *StoreSettings
}

func NewLdapStore(sessionStore sessions.Store, users map[string]AuthenticPerson, sessionName string, sessionLifetime int, settings *StoreSettings) (Store, error) {
	var ldapURL, bindUsername, bindPassword string
	if url, err := url.Parse(settings.URI); err == nil {
		if url.User != nil {
			bindUsername = url.User.Username()
			bindPassword, _ = url.User.Password()
		}
		ldapURL = fmt.Sprintf("%s://%s", url.Scheme, url.Host)
	} else {
		return nil, err
	}

	return &ldapStore{
		embeddedStore: embeddedStore{
			sessionStore:    sessionStore,
			users:           users,
			sessionName:     sessionName,
			sessionLifetime: sessionLifetime,
		},
		ldapURL:           ldapURL,
		baseDN:            settings.Parameters["base_dn"].(string),
		bindUser:          bindUsername,
		bindPassword:      bindPassword,
		detailsAttributes: settings.Parameters["details_attributes"].([]string),
		userIDAttr:        settings.Parameters["user_id_attribute"].(string),
		groupIDAttr:       settings.Parameters["group_id_attribute"].(string),
		settings:          settings,
	}, nil
}

func (p ldapStore) queryGroups(conn *ldap.Conn, userDN string) ([]string, error) {
	var groups []string

	log.Printf("LDAP: %s; %%s = %s", p.settings.GroupsQuery, userDN)
	// (&(objectClass=groupOfUniqueNames)(uniquemember=%s))
	var ldapGroupsSearch = ldap.NewSearchRequest(
		p.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(p.settings.GroupsQuery, ldap.EscapeFilter(userDN)),
		[]string{p.groupIDAttr},
		nil,
	)
	if groupsResults, err := conn.Search(ldapGroupsSearch); err == nil {
		for _, group := range groupsResults.Entries {
			if strings.EqualFold("DN", p.groupIDAttr) {
				groups = append(groups, group.DN)
			} else {
				groups = append(groups, group.GetAttributeValue(p.groupIDAttr))
			}
		}
	} else {
		return nil, err
	}

	return groups, nil
}

func (p ldapStore) queryDetails(conn *ldap.Conn, userID string) (string, map[string]any, error) {
	var details = make(map[string]any)
	var userDN string

	log.Printf("LDAP: %s; %%s = %s", p.settings.DetailsQuery, userID)
	// (&(objectClass=person)(uid=%s))
	var ldapSearch = ldap.NewSearchRequest(
		p.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(p.settings.DetailsQuery, userID),
		p.detailsAttributes,
		nil,
	)
	if results, err := conn.Search(ldapSearch); err == nil {
		if len(results.Entries) == 1 {
			var entry = results.Entries[0]
			userDN = entry.DN
			for _, key := range p.detailsAttributes {
				details[key] = entry.GetAttributeValue(key)
			}
		} else {
			return "", nil, ErrPersonNotFound
		}
	} else {
		return "", nil, err
	}

	return userDN, details, nil
}

func (p ldapStore) Authenticate(userID, password string) (string, error) {
	var realUserID, found = p.embeddedStore.Authenticate(userID, password)
	if found == nil {
		return realUserID, nil
	}

	var conn, err = ldap.DialURL(p.ldapURL)
	if err != nil {
		log.Printf("!!! ldap connection error: %v", err)
		return "", err
	}
	defer conn.Close()

	if p.bindUser != "" && p.bindPassword != "" {
		if err = conn.Bind(p.bindUser, p.bindPassword); err != nil {
			log.Printf("!!! ldap bind error: %v", err)
			return "", err
		}
	}

	// (&(objectClass=person)(uid=%s))
	log.Printf("LDAP: %s; %%s = %s", p.settings.CredentialsQuery, userID)
	var ldapSearch = ldap.NewSearchRequest(
		p.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(p.settings.CredentialsQuery, ldap.EscapeFilter(userID)),
		[]string{"dn", p.userIDAttr},
		nil,
	)
	var results *ldap.SearchResult
	if results, err = conn.Search(ldapSearch); err == nil {
		if len(results.Entries) == 1 {
			var entry = results.Entries[0]
			if err = conn.Bind(entry.DN, password); err == nil {
				return entry.GetAttributeValue(p.userIDAttr), nil
			} else {
				log.Printf("!!! Authenticate failed: %v", err)
			}
		} else {
			log.Printf("!!! Person not found: %s", userID)
		}
	} else {
		log.Printf("!!! Query for person failed: %v", err)
		return "", err
	}

	return "", ErrAuthenticationFailed
}

func (p ldapStore) Lookup(userID string) (Person, error) {
	var person, err = p.embeddedStore.Lookup(userID)
	if err == nil {
		return person, nil
	}

	var details map[string]any
	var groups []string
	var conn *ldap.Conn
	var userDN string

	conn, err = ldap.DialURL(p.ldapURL)
	if err != nil {
		log.Printf("!!! ldap connection error: %v", err)
		return Person{}, err
	}
	defer conn.Close()

	if p.bindUser != "" && p.bindPassword != "" {
		if err = conn.Bind(p.bindUser, p.bindPassword); err != nil {
			log.Printf("!!! ldap bind error: %v", err)
			return Person{}, err
		}
	}

	if userDN, details, err = p.queryDetails(conn, userID); err != nil {
		log.Printf("!!! Query for details failed: %v", err)
		return Person{}, err
	}

	if groups, err = p.queryGroups(conn, userDN); err != nil {
		log.Printf("!!! Query for groups failed: %v", err)
		return Person{}, err
	}

	return Person{Groups: groups, Details: details}, nil
}
