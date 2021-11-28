package oauth2

func IsAnyEmpty(strings ...string) bool {
	for _, s := range strings {
		if s == "" {
			return true
		}
	}
	return false
}
