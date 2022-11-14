package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/cwkr/auth-server/internal/htmlutil"
	"github.com/cwkr/auth-server/internal/maputil"
	"github.com/cwkr/auth-server/internal/oauth2"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/cwkr/auth-server/internal/server"
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
	settings     *server.Settings
	tokenService oauth2.TokenCreator
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
	settings = server.NewDefaultSettings()

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

	if settings.LoginTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(settings.LoginTemplate, "@"))
		log.Printf("Loading login form template from %s", filename)
		err = server.LoadLoginTemplate(filename)
		if err != nil {
			panic(err)
		}
	}

	if saveSettings {
		log.Printf("Saving settings to %s", settingsFilename)
		configJson, _ := json.MarshalIndent(settings, "", "  ")
		if err := os.WriteFile(settingsFilename, configJson, 0644); err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	var scope = strings.TrimSpace(oauth2.OIDCDefaultScope + " " + settings.ExtraScope)

	tokenService, err = oauth2.NewTokenService(
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

	var basePath = ""
	var sessionStore = sessions.NewCookieStore([]byte(settings.SessionSecret))
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.MaxAge = 0
	sessionStore.Options.SameSite = http.SameSiteStrictMode
	if issuerUrl, err := url.Parse(settings.Issuer); err == nil {
		if issuerUrl.Path != "/" {
			basePath = strings.TrimSuffix(issuerUrl.Path, "/")
			sessionStore.Options.Path = basePath
		}
		if issuerUrl.Scheme == "https" {
			sessionStore.Options.Secure = true
		}
	} else {
		panic(err)
	}

	var clients, users = maputil.LowerKeys(settings.Clients), maputil.LowerKeys(settings.Users)

	var peopleStore people.Store
	if settings.PeopleStore != nil {
		if strings.HasPrefix(settings.PeopleStore.URI, "postgresql:") {
			if peopleStore, err = people.NewSqlStore(sessionStore, users, int64(settings.SessionTTL), settings.PeopleStore); err != nil {
				panic(err)
			}
		} else if strings.HasPrefix(settings.PeopleStore.URI, "ldap:") || strings.HasPrefix(settings.PeopleStore.URI, "ldaps:") {
			if peopleStore, err = people.NewLdapStore(sessionStore, users, int64(settings.SessionTTL), settings.PeopleStore); err != nil {
				panic(err)
			}
		} else {
			panic(errors.New("unsupported or empty store uri: " + settings.PeopleStore.URI))
		}
	} else {
		peopleStore = people.NewEmbeddedStore(sessionStore, users, int64(settings.SessionTTL))
	}

	var router = mux.NewRouter()

	router.NotFoundHandler = htmlutil.NotFoundHandler(basePath)
	router.Handle(basePath+"/", server.IndexHandler(basePath, settings, scope)).
		Methods(http.MethodGet)
	router.Handle(basePath+"/style.css", server.StyleHandler()).
		Methods(http.MethodGet)
	router.Handle("/favicon.ico", server.FaviconHandler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/favicon-16x16.png", server.Favicon16x16Handler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/favicon-32x32.png", server.Favicon32x32Handler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/login", server.LoginHandler(basePath, peopleStore, clients, settings.Issuer, settings.SessionName)).
		Methods(http.MethodGet, http.MethodPost)
	router.Handle(basePath+"/logout", server.LogoutHandler(basePath, settings, sessionStore, clients))
	router.Handle(basePath+"/health", server.HealthHandler(peopleStore)).
		Methods(http.MethodGet)

	router.Handle(basePath+"/jwks", oauth2.JwksHandler(settings.AllKeys())).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle(basePath+"/token", oauth2.TokenHandler(tokenService, peopleStore, clients, settings.EnableRefreshTokenRotation)).
		Methods(http.MethodOptions, http.MethodPost)
	router.Handle(basePath+"/authorize", oauth2.AuthorizeHandler(basePath, tokenService, peopleStore, clients, scope, settings.SessionName)).
		Methods(http.MethodGet)
	router.Handle(basePath+"/.well-known/openid-configuration", oauth2.DiscoveryDocumentHandler(settings.Issuer, scope)).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle(basePath+"/userinfo", oauth2.UserInfoHandler(peopleStore, tokenService, settings.AccessTokenExtraClaims)).
		Methods(http.MethodGet, http.MethodOptions)

	if !settings.DisablePeopleAPI {
		router.Handle(basePath+"/api/{version}/people/{user_id}", server.PeopleAPIHandler(peopleStore, settings.PeopleAPICustomVersions)).
			Methods(http.MethodGet, http.MethodOptions)
	}

	log.Printf("Listening on http://localhost:%d%s/", settings.Port, basePath)
	err = http.ListenAndServe(fmt.Sprintf(":%d", settings.Port), router)
	if err != nil {
		panic(err)
	}
}
