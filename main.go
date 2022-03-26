package main

import (
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/oauth2"
	"github.com/cwkr/auth-server/server"
	"github.com/cwkr/auth-server/userstore"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"os"
)

var (
	settings     *server.Settings
	tokenService oauth2.TokenService
)

func main() {
	var err error
	var configFilename string
	var showHelp bool
	var initConfig bool

	gob.Register(userstore.User{})

	log.SetOutput(os.Stdout)

	flag.StringVar(&configFilename, "config", "auth-server.json", "config file")
	flag.BoolVar(&showHelp, "help", false, "print help and exit")
	flag.BoolVar(&initConfig, "init", false, "init config and exit")
	flag.Parse()

	if showHelp {
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Set defaults
	settings = server.NewDefaultSettings()

	configBytes, err := os.ReadFile(configFilename)
	if err == nil {
		err = json.Unmarshal(configBytes, settings)
		if err != nil {
			panic(err)
		}
	}

	err = settings.LoadKey(initConfig)
	if err != nil {
		panic(err)
	}

	tokenService, err = oauth2.NewTokenService(
		settings.PrivateKey(),
		settings.Issuer,
		settings.Scopes,
		settings.AccessTokenLifetime,
		settings.Claims,
	)
	if err != nil {
		panic(err)
	}

	if initConfig {
		log.Printf("Initializing config file %s", configFilename)
		configJson, _ := json.MarshalIndent(settings, "", "  ")
		err := os.WriteFile(configFilename, configJson, 0644)
		if err != nil {
			panic(err)
		}
		os.Exit(0)
	}
	sessionSecretBytes, err := base64.URLEncoding.DecodeString(settings.SessionSecret)
	if err != nil {
		panic(err)
	}
	var sessionStore = sessions.NewCookieStore(sessionSecretBytes)
	sessionStore.Options.HttpOnly = true

	var router = mux.NewRouter()

	router.NotFoundHandler = htmlutil.NotFoundHandler()
	router.Handle("/", server.IndexHandler(settings)).Methods(http.MethodGet)
	router.Handle("/jwks", oauth2.JwksHandler(settings.PublicKey())).Methods(http.MethodGet)
	router.Handle("/token", oauth2.TokenHandler(tokenService, settings.Clients)).Methods(http.MethodPost)
	router.Handle("/auth", oauth2.AuthHandler(tokenService, settings, settings.Clients, sessionStore, settings.SessionID)).Methods(http.MethodGet)
	router.Handle("/login", server.LoginHandler(settings, sessionStore)).Methods(http.MethodGet, http.MethodPost)
	router.Handle("/logout", server.LogoutHandler(settings, sessionStore))

	log.Printf("Listening on http://localhost:%d/", settings.Port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", settings.Port), router)
	if err != nil {
		panic(err)
	}
}
