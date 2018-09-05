// Package env implements an environment loader.
//
// Keys will be converted to SCREAMING_SNAKE_CASE before being looked up in
// the environment.
//
// If a Prefix option is given, the prefix will be uppercased and prepended to
// the key.
//
// For example:
//
// 	e := env.New(env.Prefix("foo"))
//	e.Lookup("bar")  // Looks for FOO_BAR in the environment
package env

import (
	"os"
	"strings"
	"unicode"
)

// Loader is a Loader that looks values up from the environment
type Loader struct {
	prefix string
}

// Lookup looks up the key in the environment. The key is converted to
// SCREAMING_SNAKE_CASE. If a prefix has been specified, it will be prepended
// to the key as PREFIX_KEY_NAME.
func (e Loader) Lookup(key string) (string, bool, error) {
	if key != strings.ToUpper(key) {
		key = nameToEnv(e.prefix, key)
	}
	val, ok := os.LookupEnv(key)
	return val, ok, nil
}

// Name returns the name of this loader
func (Loader) Name() string {
	return "env"
}

// Explicit returns whether this loader needs to be specified in the field's
// loader chain.
func (Loader) Explicit() bool {
	return false
}

// New creates an env loader
func New(options ...func(*Loader)) *Loader {
	loader := &Loader{}
	for _, option := range options {
		option(loader)
	}
	return loader
}

// Prefix sets a prefix for env lookup
func Prefix(prefix string) func(*Loader) {
	return func(e *Loader) {
		e.prefix = prefix
	}
}

func nameToEnv(prefix, name string) string {
	snakeName := snakeCaser(name)
	if len(prefix) > 0 {
		return strings.ToUpper(prefix) + "_" + snakeName
	}
	return snakeName
}

func snakeCaser(name string) string {
	var result string
	runes := []rune(name)

	for i := 0; i < len(runes); i++ {
		char := name[i : i+1]

		if i == 0 {
			result += strings.ToUpper(char)
			continue
		}

		if unicode.IsUpper(runes[i]) && name[i-1:i] != "_" {
			result += "_"
		}

		result += strings.ToUpper(char)
	}

	return result
}
