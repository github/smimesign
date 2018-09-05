// Package vault implements a Loader that looks values up in vault using octovault.
//
// To use the vault loader, set the VAULT_SOCKET and VAULT_TOKEN appropriately
// (see octovault documentation).
//
// The vault loader is an explicit loader, meaning it must be specified in the
// field's struct tag and will not be searched as part of the default load
// chain.
//
// 	type Config struct {
// 		Foo string `config:",vault"`  // Will load from vault
//		Bar string `config:""`        // Will not load from vault
// 	}
//
package vault

import (
	"strings"

	"github.com/github/go/octovault"
)

// Loader is a config.Loader that looks values up in vault
type Loader struct {
	application string
	environment string
	client      *octovault.Octovault
	setupErr    error
}

// Lookup looks the key up in vault under the path
func (v Loader) Lookup(key string) (string, bool, error) {
	k := strings.ToLower(key)

	val, err := v.client.GetSecret(v.application, v.environment, k)
	if err != nil {
		return "", false, err
	}

	return val, len(val) != 0, nil
}

// New creates a new vault loader with the given path
func New(socket, application, environment string) *Loader {
	client := octovault.New(octovault.Config{
		VaultSocket: socket,
	})

	return &Loader{
		application: application,
		environment: environment,
		client:      client,
	}
}

// Name returns the name of this loader
func (Loader) Name() string {
	return "vault"
}

// Explicit indicates that this loader must be explicitly specified in a
// field's config tag. It will not be part of the default load chain.
func (Loader) Explicit() bool {
	return true
}
