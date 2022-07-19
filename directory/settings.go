package directory

type StoreSettings struct {
	URI              string            `json:"uri,omitempty"`
	CredentialsQuery string            `json:"credentials_query,omitempty"`
	GroupsQuery      string            `json:"groups_query,omitempty"`
	DetailsQuery     string            `json:"details_query,omitempty"`
	Parameters       map[string]string `json:"parameters,omitempty"`
}
