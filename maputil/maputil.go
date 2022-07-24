package maputil

import "strings"

func LowerKeys[T any](m map[string]T) map[string]T {
	var lowerMap = make(map[string]T, len(m))
	for key, value := range m {
		lowerMap[strings.ToLower(key)] = value
	}
	return lowerMap
}
