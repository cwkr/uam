package people

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
	ldapURL        string
	baseDN         string
	bindUser       string
	bindPassword   string
	attributes     []string
	userIDAttr     string
	groupIDAttr    string
	birthdateAttr  string
	givenNameAttr  string
	familyNameAttr string
	emailAttr      string
	settings       *StoreSettings
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

	var attributes []string
	for name, value := range settings.Parameters {
		if strings.HasSuffix(name, "_attribute") && !strings.HasSuffix(name, "_id_attribute") && value != "" {
			attributes = append(attributes, value)
		}
	}

	return &ldapStore{
		embeddedStore: embeddedStore{
			sessionStore:    sessionStore,
			users:           users,
			sessionName:     sessionName,
			sessionLifetime: sessionLifetime,
		},
		ldapURL:        ldapURL,
		baseDN:         settings.Parameters["base_dn"],
		bindUser:       bindUsername,
		bindPassword:   bindPassword,
		attributes:     attributes,
		userIDAttr:     settings.Parameters["user_id_attribute"],
		groupIDAttr:    settings.Parameters["group_id_attribute"],
		birthdateAttr:  settings.Parameters["birthdate_attribute"],
		givenNameAttr:  settings.Parameters["given_name_attribute"],
		familyNameAttr: settings.Parameters["family_name_attribute"],
		emailAttr:      settings.Parameters["email_attribute"],
		settings:       settings,
	}, nil
}

func (p ldapStore) queryGroups(conn *ldap.Conn, userDN string) ([]string, error) {

	if p.settings.GroupsQuery == "" {
		return []string{}, nil
	}

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

func (p ldapStore) queryDetails(conn *ldap.Conn, userID string) (string, *Person, error) {
	var person Person
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
		p.attributes,
		nil,
	)
	if results, err := conn.Search(ldapSearch); err == nil {
		if len(results.Entries) == 1 {
			var entry = results.Entries[0]
			userDN = entry.DN
			if p.birthdateAttr != "" {
				person.Birthdate = entry.GetAttributeValue(p.birthdateAttr)
			}
			if p.givenNameAttr != "" {
				person.GivenName = entry.GetAttributeValue(p.givenNameAttr)
			}
			if p.familyNameAttr != "" {
				person.FamilyName = entry.GetAttributeValue(p.familyNameAttr)
			}
			if p.emailAttr != "" {
				person.Email = entry.GetAttributeValue(p.emailAttr)
			}
		} else {
			return "", nil, ErrPersonNotFound
		}
	} else {
		return "", nil, err
	}

	return userDN, &person, nil
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

func (p ldapStore) Lookup(userID string) (*Person, error) {
	var person, err = p.embeddedStore.Lookup(userID)
	if err == nil {
		return person, nil
	}

	var groups []string
	var conn *ldap.Conn
	var userDN string

	conn, err = ldap.DialURL(p.ldapURL)
	if err != nil {
		log.Printf("!!! ldap connection error: %v", err)
		return nil, err
	}
	defer conn.Close()

	if p.bindUser != "" && p.bindPassword != "" {
		if err = conn.Bind(p.bindUser, p.bindPassword); err != nil {
			log.Printf("!!! ldap bind error: %v", err)
			return nil, err
		}
	}

	if userDN, person, err = p.queryDetails(conn, userID); err != nil {
		log.Printf("!!! Query for details failed: %v", err)
		return nil, err
	}

	if groups, err = p.queryGroups(conn, userDN); err != nil {
		log.Printf("!!! Query for groups failed: %v", err)
		return nil, err
	}
	person.Groups = groups

	return person, nil
}
