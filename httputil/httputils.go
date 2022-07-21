package httputil

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func RedirectFragment(w http.ResponseWriter, r *http.Request, url string, params url.Values) {
	http.Redirect(w, r, fmt.Sprintf("%s#%s", url, params.Encode()), http.StatusFound)
}

func RedirectQuery(w http.ResponseWriter, r *http.Request, url string, params url.Values) {
	http.Redirect(w, r, fmt.Sprintf("%s?%s", url, params.Encode()), http.StatusFound)
}

func ExtractAccessToken(r *http.Request) string {
	var fields = strings.Fields(r.Header.Get("Authorization"))
	if len(fields) == 2 && strings.EqualFold("Bearer", fields[0]) {
		return fields[1]
	}
	return ""
}
