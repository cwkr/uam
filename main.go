package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/cwkr/auth-server/internal/htmlutil"
	"github.com/cwkr/auth-server/internal/maputil"
	oauth22 "github.com/cwkr/auth-server/internal/oauth2"
	people2 "github.com/cwkr/auth-server/internal/people"
	server2 "github.com/cwkr/auth-server/internal/server"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/tidwall/jsonc"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var (
	settings     *server2.Settings
	tokenService oauth22.TokenCreator
)

func main() {
	var err error
	var settingsFilename string
	var saveSettings bool

	log.SetOutput(os.Stdout)

	flag.StringVar(&settingsFilename, "config", "auth-server.json", "config file name")
	flag.BoolVar(&saveSettings, "save", false, "save config and exit")
	flag.Parse()

	// Set defaults
	settings = server2.NewDefaultSettings()

	log.Printf("Loading settings from %s", settingsFilename)
	configBytes, err := os.ReadFile(settingsFilename)
	if err == nil {
		err = json.Unmarshal(jsonc.ToJSON(configBytes), settings)
		if err != nil {
			panic(err)
		}
	} else {
		log.Printf("%v", err)
	}

	err = settings.LoadKeys(filepath.Dir(settingsFilename), saveSettings)
	if err != nil {
		panic(err)
	}

	if saveSettings {
		log.Printf("Saving settings to %s", settingsFilename)
		configJson, _ := json.MarshalIndent(settings, "", "  ")
		if err := os.WriteFile(settingsFilename, configJson, 0644); err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	var scope = strings.TrimSpace(oauth22.OIDCDefaultScope + " " + settings.ExtraScope)

	tokenService, err = oauth22.NewTokenService(
		settings.PrivateKey(),
		settings.KeyID(),
		settings.Issuer,
		scope,
		int64(settings.AccessTokenTTL),
		int64(settings.RefreshTokenTTL),
		int64(settings.IDTokenTTL),
		settings.AccessTokenExtraClaims,
		settings.IDTokenExtraClaims,
	)
	if err != nil {
		panic(err)
	}

	var sessionStore = sessions.NewCookieStore([]byte(settings.SessionSecret))
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.MaxAge = 0
	sessionStore.Options.SameSite = http.SameSiteStrictMode
	if issuerUrl, err := url.Parse(settings.Issuer); err == nil {
		if issuerUrl.Path != "/" {
			sessionStore.Options.Path = strings.TrimSuffix(issuerUrl.Path, "/")
		}
		if issuerUrl.Scheme == "https" {
			sessionStore.Options.Secure = true
		}
	} else {
		panic(err)
	}

	var clients, users = maputil.LowerKeys(settings.Clients), maputil.LowerKeys(settings.Users)

	var peopleStore people2.Store
	if settings.PeopleStore != nil {
		if strings.HasPrefix(settings.PeopleStore.URI, "postgresql:") {
			if peopleStore, err = people2.NewSqlStore(sessionStore, users, settings.SessionName, int64(settings.SessionTTL), settings.PeopleStore); err != nil {
				panic(err)
			}
		} else if strings.HasPrefix(settings.PeopleStore.URI, "ldap:") || strings.HasPrefix(settings.PeopleStore.URI, "ldaps:") {
			if peopleStore, err = people2.NewLdapStore(sessionStore, users, settings.SessionName, int64(settings.SessionTTL), settings.PeopleStore); err != nil {
				panic(err)
			}
		} else {
			panic(errors.New("unsupported or empty store uri: " + settings.PeopleStore.URI))
		}
	} else {
		peopleStore = people2.NewEmbeddedStore(sessionStore, users, settings.SessionName, int64(settings.SessionTTL))
	}

	var router = mux.NewRouter()

	router.NotFoundHandler = htmlutil.NotFoundHandler()
	router.Handle("/", server2.IndexHandler(settings, peopleStore, scope)).
		Methods(http.MethodGet)
	router.Handle("/style", server2.StyleHandler()).
		Methods(http.MethodGet)
	router.Handle("/favicon.ico", server2.FaviconHandler()).
		Methods(http.MethodGet)
	router.Handle("/login", server2.LoginHandler(peopleStore, settings.Issuer)).
		Methods(http.MethodGet, http.MethodPost)
	router.Handle("/logout", server2.LogoutHandler(settings, sessionStore, clients))
	router.Handle("/health", server2.HealthHandler(peopleStore)).
		Methods(http.MethodGet)

	router.Handle("/jwks", oauth22.JwksHandler(settings.AllKeys())).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle("/token", oauth22.TokenHandler(tokenService, peopleStore, clients, settings.EnableRefreshTokenRotation)).
		Methods(http.MethodOptions, http.MethodPost)
	router.Handle("/authorize", oauth22.AuthorizeHandler(tokenService, peopleStore, clients, scope)).
		Methods(http.MethodGet)
	router.Handle("/.well-known/openid-configuration", oauth22.DiscoveryDocumentHandler(settings.Issuer, scope)).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle("/userinfo", oauth22.UserInfoHandler(peopleStore, tokenService, settings.AccessTokenExtraClaims, settings.SessionName)).
		Methods(http.MethodGet, http.MethodOptions)

	if !settings.DisablePeopleAPI {
		router.Handle("/api/{version}/people/{user_id}", server2.PeopleAPIHandler(peopleStore, settings.PeopleAPICustomVersions)).
			Methods(http.MethodGet, http.MethodOptions)
	}

	log.Printf("Listening on http://localhost:%d/", settings.Port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", settings.Port), router)
	if err != nil {
		panic(err)
	}
}
