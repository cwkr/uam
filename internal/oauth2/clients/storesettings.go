package clients

type StoreSettings struct {
	URI               string `json:"uri,omitempty"`
	Query             string `json:"query,omitempty"`
	QuerySessionNames string `json:"query_session_names,omitempty"`
}
