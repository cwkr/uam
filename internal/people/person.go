package people

type Person struct {
	Birthdate  string   `json:"birthdate,omitempty" sql:"birthdate"`
	Department string   `json:"department,omitempty" sql:"department,omitempty"`
	Email      string   `json:"email,omitempty" sql:"email"`
	FamilyName string   `json:"family_name,omitempty" sql:"family_name"`
	GivenName  string   `json:"given_name,omitempty" sql:"given_name"`
	Groups     []string `json:"groups,omitempty" sql:"-"`
}
