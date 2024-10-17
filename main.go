package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cwkr/auth-server/internal/fileutil"
	"github.com/cwkr/auth-server/internal/htmlutil"
	"github.com/cwkr/auth-server/internal/maputil"
	"github.com/cwkr/auth-server/internal/oauth2"
	"github.com/cwkr/auth-server/internal/oauth2/clients"
	"github.com/cwkr/auth-server/internal/oauth2/trl"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/cwkr/auth-server/internal/server"
	"github.com/cwkr/auth-server/middleware"
	"github.com/cwkr/auth-server/settings"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hjson/hjson-go/v4"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var version = "v0.6.x"

func main() {
	var (
		serverSettings   *settings.Server
		tokenCreator     oauth2.TokenCreator
		tokenVerifier    middleware.TokenVerifier
		peopleStore      people.Store
		trlStore         trl.Store
		clientStore      clients.Store
		err              error
		configFilename   string
		settingsFilename string
		setClientID      string
		setClientSecret  string
		setUserID        string
		setPassword      string
		setGivenName     string
		setFamilyName    string
		setEmail         string
		setDepartment    string
		keySize          int
		keyID            string
		saveSettings     bool
		printVersion     bool
		setPort          int
	)

	log.SetOutput(os.Stdout)

	flag.StringVar(&configFilename, "config", "", "config file name")
	flag.StringVar(&setClientID, "client-id", "", "set client id")
	flag.StringVar(&setClientSecret, "client-secret", "", "set client secret")
	flag.StringVar(&setUserID, "user-id", "", "set user id")
	flag.StringVar(&setPassword, "password", "", "set user password")
	flag.StringVar(&setGivenName, "given-name", "", "set user given name")
	flag.StringVar(&setFamilyName, "family-name", "", "set user family name")
	flag.StringVar(&setEmail, "email", "", "set user email")
	flag.StringVar(&setDepartment, "department", "", "set user department")
	flag.IntVar(&keySize, "key-size", 2048, "generated signing key size")
	flag.StringVar(&keyID, "key-id", "sigkey", "set generated signing key id")
	flag.BoolVar(&saveSettings, "save", false, "save config and exit")
	flag.BoolVar(&printVersion, "version", false, "print version and exit")
	flag.IntVar(&setPort, "port", 6080, "http server port")
	flag.Parse()

	if printVersion {
		fmt.Println(version)
		os.Exit(0)
	} else {
		log.Printf("Starting Auth Server %s built with %s", version, runtime.Version())
	}

	// Set defaults
	serverSettings = settings.NewDefault(setPort)

	settingsFilename = fileutil.ProbeSettingsFilename(configFilename)

	if fileutil.FileExists(settingsFilename) {
		log.Printf("Loading settings from %s", settingsFilename)
		if bytes, err := os.ReadFile(settingsFilename); err == nil {
			options := hjson.DefaultDecoderOptions()
			options.DisallowUnknownFields = true
			options.DisallowDuplicateKeys = true
			if err := hjson.UnmarshalWithOptions(bytes, serverSettings, options); err != nil {
				log.Fatalf("!!! %s", err)
			}
		} else {
			log.Fatalf("!!! %s", err)
		}
	}

	if serverSettings.Key == "" {
		log.Printf("Generating %d bit RSA key with ID %q", keySize, keyID)
		if err := serverSettings.GenerateSigningKey(keySize, keyID); err != nil {
			log.Fatalf("!!! %s", err)
		}
	}

	if err := serverSettings.LoadKeys(filepath.Dir(settingsFilename)); err != nil {
		log.Fatalf("!!! %s", err)
	}

	if serverSettings.LoginTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.LoginTemplate, "@"))
		log.Printf("Loading login form template from %s", filename)
		err = server.LoadLoginTemplate(filename)
		if err != nil {
			log.Fatalf("!!! %s", err)
		}
	}

	if serverSettings.LogoutTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.LogoutTemplate, "@"))
		log.Printf("Loading logout template from %s", filename)
		err = server.LoadLogoutTemplate(filename)
		if err != nil {
			log.Fatalf("!!! %s", err)
		}
	}

	if setClientID != "" {
		if serverSettings.Clients == nil {
			serverSettings.Clients = map[string]clients.Client{}
		}
		var client = serverSettings.Clients[setClientID]
		if setClientSecret != "" {
			if secretHash, err := bcrypt.GenerateFromPassword([]byte(setClientSecret), 5); err != nil {
				log.Fatalf("!!! %s", err)
			} else {
				client.SecretHash = string(secretHash)
			}
		}
		serverSettings.Clients[setClientID] = client
	}

	if setUserID != "" {
		if serverSettings.Users == nil {
			serverSettings.Users = map[string]people.AuthenticPerson{}
		}
		var user = serverSettings.Users[setUserID]
		if setPassword != "" {
			if passwordHash, err := bcrypt.GenerateFromPassword([]byte(setPassword), 5); err != nil {
				log.Fatalf("!!! %s", err)
			} else {
				user.PasswordHash = string(passwordHash)
			}
		}
		if setGivenName != "" {
			user.GivenName = setGivenName
		}
		if setFamilyName != "" {
			user.FamilyName = setFamilyName
		}
		if setEmail != "" {
			user.Email = setEmail
		}
		if setDepartment != "" {
			user.Department = setDepartment
		}
		if user.PasswordHash == "" {
			log.Fatal("!!! missing password")
		}
		serverSettings.Users[setUserID] = user
	}

	if setPort != serverSettings.Port {
		serverSettings.Port = setPort
	}

	if saveSettings {
		log.Printf("Saving settings to %s", settingsFilename)
		var configBytes []byte
		if filepath.Ext(strings.ToLower(settingsFilename)) == ".hjson" {
			options := hjson.DefaultOptions()
			options.QuoteAlways = true
			options.EmitRootBraces = false
			options.IndentBy = "  "
			configBytes, _ = hjson.MarshalWithOptions(serverSettings, options)
		} else {
			configBytes, _ = json.MarshalIndent(serverSettings, "", "  ")
		}
		if err := os.WriteFile(settingsFilename, configBytes, 0644); err != nil {
			log.Fatalf("!!! %s", err)
		}
		os.Exit(0)
	}

	var scope = strings.TrimSpace(oauth2.OIDCDefaultScope + " " + serverSettings.ExtraScope)

	tokenCreator, err = oauth2.NewTokenCreator(
		serverSettings.PrivateKey(),
		serverSettings.KeyID(),
		serverSettings.Issuer,
		scope,
		int64(serverSettings.AccessTokenTTL),
		int64(serverSettings.RefreshTokenTTL),
		int64(serverSettings.IDTokenTTL),
		serverSettings.AccessTokenExtraClaims,
		serverSettings.IDTokenExtraClaims,
	)
	if err != nil {
		log.Fatalf("!!! %s", err)
	}

	tokenVerifier = middleware.NewTokenVerifier(serverSettings.AllKeys())

	var basePath = ""
	var sessionStore = sessions.NewCookieStore([]byte(serverSettings.SessionSecret))
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.MaxAge = 0
	sessionStore.Options.SameSite = http.SameSiteLaxMode
	if issuerUrl, err := url.Parse(serverSettings.Issuer); err == nil {
		if issuerUrl.Path != "/" {
			basePath = strings.TrimSuffix(issuerUrl.Path, "/")
			sessionStore.Options.Path = basePath
			sessionStore.Options.Secure = false
		}
		if issuerUrl.Scheme == "https" {
			sessionStore.Options.Secure = true
		}
	} else {
		log.Fatalf("!!! %s", err)
	}

	var dbs = make(map[string]*sql.DB)

	var users = maputil.LowerKeys(serverSettings.Users)

	if serverSettings.PeopleStore != nil {
		if strings.HasPrefix(serverSettings.PeopleStore.URI, "postgresql:") {
			if peopleStore, err = people.NewSqlStore(sessionStore, users, int64(serverSettings.SessionTTL), dbs, serverSettings.PeopleStore); err != nil {
				log.Fatalf("!!! %s", err)
			}
		} else if strings.HasPrefix(serverSettings.PeopleStore.URI, "ldap:") || strings.HasPrefix(serverSettings.PeopleStore.URI, "ldaps:") {
			if peopleStore, err = people.NewLdapStore(sessionStore, users, int64(serverSettings.SessionTTL), serverSettings.PeopleStore); err != nil {
				log.Fatalf("!!! %s", err)
			}
		} else {
			log.Fatalf("!!! unsupported or empty store uri: %s", serverSettings.PeopleStore.URI)
		}
	} else {
		peopleStore = people.NewEmbeddedStore(sessionStore, users, int64(serverSettings.SessionTTL))
	}

	if serverSettings.ClientStore != nil {
		if strings.HasPrefix(serverSettings.ClientStore.URI, "postgresql:") {
			if clientStore, err = clients.NewSqlStore(serverSettings.Clients, dbs, serverSettings.ClientStore); err != nil {
				log.Fatalf("!!! %s", err)
			}
		} else {
			log.Fatalf("!!! unsupported or empty store uri: %s", serverSettings.ClientStore.URI)
		}
	} else {
		clientStore = clients.NewInMemoryClientStore(serverSettings.Clients)
	}

	if serverSettings.TRLStore != nil {
		if strings.HasPrefix(serverSettings.TRLStore.URI, "postgresql:") {
			if trlStore, err = trl.NewSqlStore(dbs, serverSettings.TRLStore); err != nil {
				log.Fatalf("!!! %s", err)
			}
		} else {
			log.Fatalf("!!! unsupported or empty store uri: %s", serverSettings.TRLStore.URI)
		}
	} else {
		trlStore = trl.NewNoopStore()
	}

	var router = mux.NewRouter()

	router.NotFoundHandler = htmlutil.NotFoundHandler(basePath)
	router.Handle(basePath+"/", server.IndexHandler(basePath, serverSettings, peopleStore, clientStore, scope, version)).
		Methods(http.MethodGet)
	router.Handle(basePath+"/style.css", server.StyleHandler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/scripts/jwt.js", server.JwtScriptHandler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/scripts/main.js", server.MainScriptHandler()).
		Methods(http.MethodGet)
	router.Handle("/favicon.ico", server.FaviconHandler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/favicon-16x16.png", server.Favicon16x16Handler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/favicon-32x32.png", server.Favicon32x32Handler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/login", server.LoginHandler(basePath, peopleStore, clientStore, serverSettings.Issuer, serverSettings.SessionName)).
		Methods(http.MethodGet, http.MethodPost)
	router.Handle(basePath+"/logout", server.LogoutHandler(basePath, serverSettings, sessionStore, clientStore))
	router.Handle(basePath+"/health", server.HealthHandler(peopleStore)).
		Methods(http.MethodGet)
	router.Handle(basePath+"/info", server.InfoHandler(version, runtime.Version())).
		Methods(http.MethodGet)

	router.Handle(basePath+"/jwks", oauth2.JwksHandler(serverSettings.AllKeys())).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle(basePath+"/token", oauth2.TokenHandler(tokenCreator, peopleStore, clientStore, trlStore, scope)).
		Methods(http.MethodOptions, http.MethodPost)
	router.Handle(basePath+"/authorize", oauth2.AuthorizeHandler(basePath, tokenCreator, peopleStore, clientStore, scope, serverSettings.SessionName)).
		Methods(http.MethodGet)
	router.Handle(basePath+"/.well-known/openid-configuration", oauth2.DiscoveryDocumentHandler(serverSettings.Issuer, scope)).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle(basePath+"/userinfo", middleware.RequireJWT(oauth2.UserInfoHandler(peopleStore, serverSettings.AccessTokenExtraClaims), tokenVerifier)).
		Methods(http.MethodGet, http.MethodOptions)

	router.Handle(basePath+"/revoke", oauth2.RevokeHandler(tokenCreator, clientStore, trlStore)).
		Methods(http.MethodPost, http.MethodOptions)

	if !serverSettings.DisableAPI {
		var lookupPersonHandler = server.LookupPersonHandler(peopleStore, serverSettings.PeopleAPICustomVersions)
		if serverSettings.PeopleAPIRequireAuthN {
			lookupPersonHandler = middleware.RequireJWT(lookupPersonHandler, tokenVerifier)
		}
		router.Handle(basePath+"/api/{version}/people/{user_id}", lookupPersonHandler).
			Methods(http.MethodGet, http.MethodOptions)
		if !peopleStore.ReadOnly() {
			router.Handle(basePath+"/api/v1/people/{user_id}", middleware.RequireJWT(server.PutPersonHandler(peopleStore), tokenVerifier)).
				Methods(http.MethodPut)
			router.Handle(basePath+"/api/v1/people/{user_id}/password", middleware.RequireJWT(server.ChangePasswordHandler(peopleStore), tokenVerifier)).
				Methods(http.MethodOptions, http.MethodPut)
		}
	}

	log.Printf("Listening on http://localhost:%d%s/", serverSettings.Port, basePath)
	err = http.ListenAndServe(fmt.Sprintf(":%d", serverSettings.Port), router)
	if err != nil {
		log.Fatalf("!!! %s", err)
	}
}
