package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/oauth2"
	"github.com/cwkr/auth-server/server"
	"github.com/cwkr/auth-server/store"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	settings     *server.Settings
	tokenService oauth2.TokenService
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
		settings.Scopes,
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

	var authenticator store.Authenticator
	if strings.HasPrefix(settings.StoreURI, "postgresql:") {
		if authenticator, err = store.NewDatabaseAuthenticator(sessionStore, settings.Users, settings.SessionID, settings.SessionLifetime,
			settings.StoreURI, settings.UserQuery, settings.GroupsQuery, settings.DetailsQuery); err != nil {
			panic(err)
		}
	} else if strings.HasPrefix(settings.StoreURI, "ldap:") || strings.HasPrefix(settings.StoreURI, "ldaps:") {
		var ldapURL, bindUsername, bindPassword, baseDN string
		if url, err := url.Parse(settings.StoreURI); err == nil {
			if url.User != nil {
				bindUsername = url.User.Username()
				bindPassword, _ = url.User.Password()
			}
			baseDN = url.Query().Get("base_dn")
			ldapURL = fmt.Sprintf("%s://%s", url.Scheme, url.Host)
		} else {
			panic(err)
		}
		if authenticator, err = store.NewDirectoryAuthenticator(sessionStore, settings.Users, settings.SessionID, settings.SessionLifetime,
			ldapURL, baseDN, bindUsername, bindPassword, settings.UserQuery, settings.GroupsQuery, settings.DetailsQuery, settings.Details); err != nil {
			panic(err)
		}
	} else if settings.StoreURI == "" {
		authenticator = store.NewEmbeddedAuthenticator(sessionStore, settings.Users, settings.SessionID, settings.SessionLifetime)
	} else {
		panic(errors.New("unsupported store uri: " + settings.StoreURI))
	}

	var router = mux.NewRouter()

	router.NotFoundHandler = htmlutil.NotFoundHandler()
	router.Handle("/", server.IndexHandler(settings, authenticator, !settings.DisablePKCE)).
		Methods(http.MethodGet)
	router.Handle("/style", server.StyleHandler()).
		Methods(http.MethodGet)
	router.Handle("/jwks", oauth2.JwksHandler(settings.AllKeys())).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle("/token", oauth2.TokenHandler(tokenService, authenticator, settings.Clients, settings.DisablePKCE)).
		Methods(http.MethodOptions, http.MethodPost)
	router.Handle("/auth", oauth2.AuthHandler(tokenService, authenticator, settings.Clients, settings.DisablePKCE)).
		Methods(http.MethodGet)
	router.Handle("/login", server.LoginHandler(settings, authenticator, sessionStore)).
		Methods(http.MethodGet, http.MethodPost)
	router.Handle("/logout", server.LogoutHandler(settings, sessionStore))
	router.Handle("/.well-known/openid-configuration", oauth2.DiscoveryDocumentHandler(settings.Issuer, settings.Scopes, settings.DisablePKCE)).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle("/me", server.MeHandler(authenticator)).
		Methods(http.MethodGet)

	log.Printf("Listening on http://localhost:%d/", settings.Port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", settings.Port), router)
	if err != nil {
		panic(err)
	}
}
