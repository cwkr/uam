package people

type Person struct {
	Birthdate  string   `json:"birthdate,omitempty"`
	Email      string   `json:"email,omitempty"`
	FamilyName string   `json:"family_name,omitempty"`
	GivenName  string   `json:"given_name,omitempty"`
	Groups     []string `json:"groups,omitempty"`
}
