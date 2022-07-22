package people

type Person struct {
	Details map[string]any `json:"details"`
	Groups  []string       `json:"groups"`
}
