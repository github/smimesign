// Package config provides a way to fill in a configuration struct from the
// environment and other loaders.
//
// Configuration begins with a struct whose exported fields can be tagged with
// `config`. When loading the values into this struct the tagged field names are
// are passed to a chain of loaders that attempt to look up values for the
// field. Fields not tagged with `config` are ignored by this package.
//
// If no loaders are given, the vaules will be pulled from the environment by
// converting the field names to SCREAMING_SNAKE_CASE for look up.
//
// Unless an env loader is explicitly placed in the chain, a non-prefixed env
// loader will always be consulted first, proceeding through the chain until
// the key is located.
//
// Loaders in the load chain are searched in the order given.
//
// The "config" key in the struct field's tag value is the default value given
// to the field, follwed by an optional comma and options.
//
// Examples:
//
//	// Field is given the default value "foo" if not found in the load chain
//	Field string `config:"foo"`
//
//	// Field is required and `Load()` will return an error if it is not
//	// found in the load chain.
//	Field string `config:",required"`
//
//	// Field will load from vault if it is not found in env. Vault is an
//	// example of an explicit loader, meaning to load from vault it must be
//	// included in the tag, it will not be part of the default load chain.
//	Field string `config:"foo,vault"
//
//	// Tags can specify their own load chain. Here field will be looked up
//	// in vault first, then fall back to the env lookup.
//	Field string `config:",vault,env"
//
//	// A lookup key can be given explicitly in the tag, avoiding trying to
//	// calculate one from the field name. Here field will be looked up in
//	// the env loader with the key FOO instead of FIELD.
//	Field string `config:",env=foo"`
//
// Loaders are responsible for determining the key name from the field name.
//
// A load chain example:
//
//	config.Load(cfg, env.New(env.Prefix("APP")), vault.New("secret/app"))
//
// This specifis an env loader that will prefix keynames with APP_ and a vault
// loader that will look up keys under the `secret/app` path.
//
// An app can specify their own loader by conforming to the `config.Loader`
// interface.
//
// This package will convert the values to their proper numeric and boolean
// types, according to the struct field's type.
//
// An example of a configuration struct:
//     type Config struct {
//         Name string    `config:"my_app"`
//         Host string    `config:"localhost"`
//         Port int       `config:"9090"`
//         AutoStart bool `config:"false"`
//     }
//
//
// On loading, the config will be loaded from the env using the following keys:
//     NAME, HOST, PORT, AUTO_START
//
package config
