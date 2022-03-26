package userstore

type User struct {
	FirstName  string   `json:"first_name"`
	LastName   string   `json:"last_name"`
	Email      string   `json:"email"`
	Department string   `json:"department"`
	Groups     []string `json:"groups"`
}
