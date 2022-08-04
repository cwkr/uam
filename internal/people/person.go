package people

type Person struct {
	Birthdate     string   `json:"birthdate,omitempty" sql:"birthdate"`
	Department    string   `json:"department,omitempty" sql:"department,omitempty"`
	Email         string   `json:"email,omitempty" sql:"email"`
	FamilyName    string   `json:"family_name,omitempty" sql:"family_name"`
	GivenName     string   `json:"given_name,omitempty" sql:"given_name"`
	Groups        []string `json:"groups,omitempty" sql:"-"`
	PhoneNumber   string   `json:"phone_number,omitempty" sql:"phone_number"`
	StreetAddress string   `json:"street_address,omitempty" sql:"street_address"`
	Locality      string   `json:"locality,omitempty" sql:"locality"`
	PostalCode    string   `json:"postal_code,omitempty" sql:"postal_code"`
}
