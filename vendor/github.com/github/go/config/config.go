package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/github/go/errors"
)

// Loader is an interface used by Load to look up values for a key.
type Loader interface {
	// Lookup performs the lookup for the key. It returns the value as a
	// string, a boolean flag indicating whether the value was found, and
	// an error.
	Lookup(string) (string, bool, error)

	// Name returns a name for the Loader. This is used in error messages
	// and tags with explicit load chains.
	Name() string

	// Explicit indicates whether or not a loader must be explicitly used
	// by a field's tag. If this returns true the loader will not run as
	// part of the default load chain, only when explicitly set in a
	// field's tag.
	Explicit() bool
}

// Load uses the loader chain to look up keys and set the values of c. c must
// be a pointer to a struct, or Load will return an error.
func Load(c interface{}, loaders ...Loader) error {
	if reflect.ValueOf(c).Kind() != reflect.Ptr {
		return errNotStructPtr
	}

	return load(newLoadChain(loaders), c)
}

// errNotStructPtr is returned when attempting to load a configuration into an
// object that is not a struct.
var errNotStructPtr = errors.New("Configuration must be a pointer to a struct")

// load peforms the actual loading. c must be a pointer or an interface.
func load(env *loadChain, c interface{}) error {
	var s reflect.Value

	switch v := c.(type) {
	case reflect.Value: // This is a nested struct
		s = v
	default:
		t := reflect.TypeOf(c).Elem()
		if t.Kind() != reflect.Struct {
			return errNotStructPtr
		}

		s = reflect.ValueOf(c).Elem()
	}

	typeOfC := s.Type()

	for i := 0; i < s.NumField(); i++ {
		tfield := typeOfC.Field(i)
		field := s.Field(i)
		name := tfield.Name

		tag, ok := tfield.Tag.Lookup("config")

		// If it's a struct and it does not have a config tag, attempt
		// to load its fields as config. If it has a config tag, treat
		// it like a normal type.
		if field.Kind() == reflect.Struct && !ok {
			if err := load(env, field.Addr().Elem()); err != nil {
				return err
			}
			continue
		}

		if !ok {
			continue
		}

		parser, ok := parsemap[field.Type()]
		if !ok {
			return fmt.Errorf("No parser for %v", field.Type())
		}

		pt, err := parseTag(tag, name)
		if err != nil {
			return err
		}

		val, ok, err := env.Lookup(pt)
		if err != nil {
			return err
		}

		if !ok {
			// If the value is absent in the loaders and the
			// current value is not the zero value, do not set the
			// default value.
			if field.Interface() != reflect.Zero(field.Type()).Interface() {
				continue
			}

			val = pt.Default
		}

		if err := parser.Parse(val, field); err != nil {
			// If the value was from a loader and parsing
			// failed, there might be a default value we
			// can fall back on.
			if ok && len(pt.Default) > 0 {
				err = parser.Parse(pt.Default, field)
				if err == nil {
					continue
				}
			}
			return errors.Wrapf(err, "config: unable to parse value for field: %q", name)
		}
	}

	return nil
}

type parsedTag struct {
	Default  string
	Field    string
	Required bool
	Chain    []lookupSpec
}

type lookupSpec struct {
	Loader string
	Key    string
}

func parseTag(tag, field string) (*parsedTag, error) {
	parts := strings.Split(tag, ",")
	pt := &parsedTag{
		Default: parts[0],
		Field:   field,
	}

	if len(parts) == 1 {
		return pt, nil
	}

	for _, p := range parts[1:] {
		lowered := strings.ToLower(p)
		switch lowered {
		case "required", "nodefault": // nodefault is legacy
			pt.Required = true
		default:
			specParts := strings.Split(p, "=")
			spec := lookupSpec{Loader: specParts[0]}

			switch len(specParts) {
			case 1:
				spec.Key = field
			case 2:
				spec.Key = specParts[1]
			default:
				return nil, fmt.Errorf("Invalid tag for field %q: %q", field, tag)
			}

			pt.Chain = append(pt.Chain, spec)
		}
	}

	return pt, nil
}
