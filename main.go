package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/oauth2"
	"github.com/cwkr/auth-server/people"
	"github.com/cwkr/auth-server/server"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	settings     *server.Settings
	tokenService oauth2.TokenCreator
)

func main() {
	var err error
	var configFilename string
	var saveConfig bool

	log.SetOutput(os.Stdout)

	flag.StringVar(&configFilename, "config", "auth-server.json", "config file name")
	flag.BoolVar(&saveConfig, "save", false, "save config and exit")
	flag.Parse()

	// Set defaults
	settings = server.NewDefaultSettings()

	configBytes, err := os.ReadFile(configFilename)
	if err == nil {
		err = json.Unmarshal(configBytes, settings)
		if err != nil {
			panic(err)
		}
	}

	err = settings.LoadKeys(saveConfig)
	if err != nil {
		panic(err)
	}

	if saveConfig {
		log.Printf("Saving config file %s", configFilename)
		configJson, _ := json.MarshalIndent(settings, "", "  ")
		if err := os.WriteFile(configFilename, configJson, 0644); err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	tokenService, err = oauth2.NewTokenService(
		settings.PrivateKey(),
		settings.KeyID(),
		settings.Issuer,
		settings.Scope,
		int64(settings.AccessTokenLifetime),
		int64(settings.RefreshTokenLifetime),
		settings.Claims,
	)
	if err != nil {
		panic(err)
	}

	var sessionStore = sessions.NewCookieStore([]byte(settings.SessionSecret))
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.MaxAge = 0

	var directoryStore people.Store
	if settings.PeopleStore != nil {
		if strings.HasPrefix(settings.PeopleStore.URI, "postgresql:") {
			if directoryStore, err = people.NewDatabaseStore(sessionStore, settings.Users, settings.SessionName, settings.SessionLifetime, settings.PeopleStore); err != nil {
				panic(err)
			}
		} else if strings.HasPrefix(settings.PeopleStore.URI, "ldap:") || strings.HasPrefix(settings.PeopleStore.URI, "ldaps:") {
			if directoryStore, err = people.NewLdapStore(sessionStore, settings.Users, settings.SessionName, settings.SessionLifetime, settings.PeopleStore); err != nil {
				panic(err)
			}
		} else {
			panic(errors.New("unsupported or empty store uri: " + settings.PeopleStore.URI))
		}
	} else {
		directoryStore = people.NewEmbeddedStore(sessionStore, settings.Users, settings.SessionName, settings.SessionLifetime)
	}

	var router = mux.NewRouter()

	router.NotFoundHandler = htmlutil.NotFoundHandler()
	router.Handle("/", server.IndexHandler(settings, directoryStore, !settings.DisablePKCE)).
		Methods(http.MethodGet)
	router.Handle("/style", server.StyleHandler()).
		Methods(http.MethodGet)
	router.Handle("/jwks", oauth2.JwksHandler(settings.AllKeys())).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle("/token", oauth2.TokenHandler(tokenService, directoryStore, settings.Clients, settings.DisablePKCE)).
		Methods(http.MethodOptions, http.MethodPost)
	router.Handle("/authorize", oauth2.AuthorizeHandler(tokenService, directoryStore, settings.Clients, settings.Scope, settings.DisablePKCE)).
		Methods(http.MethodGet)
	router.Handle("/login", server.LoginHandler(settings, directoryStore, sessionStore)).
		Methods(http.MethodGet, http.MethodPost)
	router.Handle("/logout", server.LogoutHandler(settings, sessionStore))
	router.Handle("/.well-known/openid-configuration", oauth2.DiscoveryDocumentHandler(settings.Issuer, settings.Scope, settings.DisablePKCE)).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle("/userinfo", oauth2.UserInfoHandler(directoryStore, tokenService, settings.Claims, settings.SessionName)).
		Methods(http.MethodGet, http.MethodOptions)
	if !settings.DisablePeopleAPI {
		router.Handle("/people/{user_id}", server.PeopleAPIHandler(directoryStore)).
			Methods(http.MethodGet, http.MethodOptions)
	}

	log.Printf("Listening on http://localhost:%d/", settings.Port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", settings.Port), router)
	if err != nil {
		panic(err)
	}
}
