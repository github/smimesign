package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"strconv"
	"time"
)

// parseFn is a function type that, given a value string, and a field to parse
// into, preforms the parse and assigns the field to that value.
//
// If the parse was unable to be completed successfully, or if the field could
// not be assigned to that parsed value, then an appropriate error should be
// returned instead.
type parseFn func(val string, field reflect.Value) error

// parser assosciates a given parseFn to a reflect.Kind that that parse function
// accepts.
type parser struct {
	// Parse is the function that preforms the parse according to the
	// definition of parseFn above.
	Parse parseFn
	// Accepts is the set of `reflect.Type`s that this parser accepts.
	//
	// A field who's type matches any of the values of reflect.Kind stored
	// in this slice is able to use this parser.
	Accepts []reflect.Type
}

// newParser instantiates and returns a new *parser, initialized with the given
// reflect.Kind and parseFn.
func newParser(fn parseFn, validAgainst ...interface{}) *parser {
	var accepts []reflect.Type
	for _, v := range validAgainst {
		accepts = append(accepts, reflect.TypeOf(v))
	}

	return &parser{
		Parse:   fn,
		Accepts: accepts,
	}
}

var (
	// stringParser is a *parser implementation for the reflect.String type.
	//
	// It simply applies the reflect.Value#SetString function directly, and
	// returns no error.
	stringParser = newParser(func(val string, field reflect.Value) error {
		field.SetString(val)

		return nil
	}, "")

	// intParser is a *parser implementation for all reflect.Int-like types.
	//
	// It parses the given value into an appropriately sized int, returning
	// the relevant error if the value was unable to be parsed, and then
	// sets the given field appropriately.
	intParser = newParser(func(val string, field reflect.Value) error {
		n, err := strconv.ParseInt(val, 10, field.Type().Bits())
		if err != nil {
			return err
		}

		field.SetInt(n)
		return nil
	}, int(0), int8(0), int16(0), int32(0), int64(0))

	// float64Parser is a *parser implementation for the
	// reflect.Float64-like types.
	//
	// It parses the given value into an appropriately sized float,
	// returning the relevant error if there was one, and then sets the
	// given field appropriately.
	float64Parser = newParser(func(val string, field reflect.Value) error {
		n, err := strconv.ParseFloat(val, field.Type().Bits())
		if err != nil {
			return err
		}

		field.SetFloat(n)
		return nil
	}, float32(0), float64(0))

	// boolParser is a *parser implementation for the reflect.Bool type.
	//
	// It parses the given value into a bool according to the rules of
	// strconv.ParseBool. If the value was unable to be parsed, the relevant
	// error will be returned. Otherwise, the field will be set with the
	// parsed value appropriately.
	boolParser = newParser(func(val string, field reflect.Value) error {
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}

		field.SetBool(b)
		return nil
	}, bool(false))

	// durationParser is a *parser impelmentation for the time.Duration
	// type.
	//
	// It parses the given value, "val" into a time.Duration according to
	// the rules of time.ParseDuration. If the value was unable to be
	// paresd, then the relevant error will be returned.
	//
	// Otherwise, the parsed time.Duration will be assigned without error.
	durationParser = newParser(func(val string, field reflect.Value) error {
		d, err := time.ParseDuration(val)
		if err != nil {
			return err
		}

		field.Set(reflect.ValueOf(d))
		return nil
	}, time.Duration(0))

	// rsaPrivKeyParser is a *parser implementation for the rsa.PrivateKey
	// type.
	//
	// It parses the given value, "val" by attempting to decode and parse
	// it into an rsa.PrivateKey. If the value is unable to be parsed, the
	// relevant error will be returned.
	rsaPrivKeyParser = newParser(func(val string, field reflect.Value) error {
		if len(val) == 0 {
			return nil
		}

		block, _ := pem.Decode([]byte(val))
		if block == nil {
			return errors.New("no private key found in data")
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
		field.Set(reflect.ValueOf(key))
		return nil
	}, &rsa.PrivateKey{})

	// rsaPubKeyParser is a *parser implementation for the rsa.PublicKey
	// type.
	//
	// It parses the given value, "val" by attempting to decode and parse
	// it into an rsa.PublicKey. If the value is unable to be parsed, the
	// relevant error will be returned.
	rsaPubKeyParser = newParser(func(val string, field reflect.Value) error {
		if len(val) == 0 {
			return nil
		}

		block, _ := pem.Decode([]byte(val))
		if block == nil {
			return errors.New("no public key found in data")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		rsaPubKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("public key was not rsa.PublicKey")
		}
		field.Set(reflect.ValueOf(rsaPubKey))
		return nil
	}, &rsa.PublicKey{})

	parsers  = []*parser{stringParser, intParser, float64Parser, boolParser, durationParser, rsaPrivKeyParser, rsaPubKeyParser}
	parsemap = map[reflect.Type]*parser{}
)

func init() {
	for _, p := range parsers {
		for _, typ := range p.Accepts {
			parsemap[typ] = p
		}
	}
}
