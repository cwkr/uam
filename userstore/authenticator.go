package userstore

type Authenticator interface {
	Authenticate(userID, password string) (User, bool)
}
