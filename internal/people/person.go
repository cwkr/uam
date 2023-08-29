package people

type Person struct {
	Birthdate     string   `json:"birthdate,omitempty" db:"birthdate"`
	Department    string   `json:"department,omitempty" db:"department"`
	Email         string   `json:"email,omitempty" db:"email"`
	FamilyName    string   `json:"family_name,omitempty" db:"family_name"`
	GivenName     string   `json:"given_name,omitempty" db:"given_name"`
	Groups        []string `json:"groups,omitempty" db:"-"`
	PhoneNumber   string   `json:"phone_number,omitempty" db:"phone_number"`
	StreetAddress string   `json:"street_address,omitempty" db:"street_address"`
	Locality      string   `json:"locality,omitempty" db:"locality"`
	PostalCode    string   `json:"postal_code,omitempty" db:"postal_code"`
}
