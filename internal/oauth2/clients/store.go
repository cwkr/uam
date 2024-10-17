package clients

type Store interface {
	Authenticate(clientID, clientSecret string) (*Client, error)
	Lookup(clientID string) (*Client, error)
	PerSessionNameMap(defaultSessionName string) (map[string][]string, error)
	Ping() error
}
