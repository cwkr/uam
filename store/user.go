package store

type User struct {
	Details map[string]interface{} `json:"details"`
	Groups  []string               `json:"groups"`
}
