package oauth2

import "regexp"

type Clients map[string]string

func (c Clients) ClientsMatchingRedirectURI(uri string) []string {
	var matches = make([]string, 0, len(c))
	for client, redirectURIPattern := range c {
		if regexp.MustCompile(redirectURIPattern).MatchString(uri) {
			matches = append(matches, client)
		}
	}
	return matches
}
