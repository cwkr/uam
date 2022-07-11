package userstore

type User struct {
	Details map[string]interface{} `json:"details"`
	Email   string                 `json:"email"`
	Groups  []string               `json:"groups"`
}
