package store

type User struct {
	Details map[string]any `json:"details"`
	Groups  []string       `json:"groups"`
}
