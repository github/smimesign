package env_test

import (
	"os"
	"testing"

	"github.com/github/go/config/env"
)

func TestLoaderProperties(t *testing.T) {
	e := env.New()

	if name := e.Name(); name != "env" {
		t.Errorf("expected loader to be named 'env', got %q", name)
	}

	if e.Explicit() {
		t.Error("expected loader to not be explicit")
	}
}

func TestLookup(t *testing.T) {
	e := env.New()

	os.Setenv("TEST_FIELD", "hello")
	defer os.Unsetenv("TEST_FIELD")

	fieldNames := []string{
		"TestField",
		"testField",
		"Test_Field",
		"test_Field",
		"test_field",
	}

	for _, field := range fieldNames {
		val, ok, err := e.Lookup(field)
		if err != nil {
			t.Error("expected err to be nil")
		}

		if !ok {
			t.Error("expected ok to be true")
		}

		if val != "hello" {
			t.Errorf("expected val to be 'hello', got %q", val)
		}
	}
}

func TestPrefixedLookup(t *testing.T) {
	e := env.New(env.Prefix("FOO"))

	os.Setenv("FOO_TEST_FIELD", "hello")
	defer os.Unsetenv("FOO_TEST_FIELD")

	fieldNames := []string{
		"TestField",
		"testField",
		"Test_Field",
		"test_Field",
		"test_field",
	}

	for _, field := range fieldNames {
		val, ok, err := e.Lookup(field)
		if err != nil {
			t.Error("expected err to be nil")
		}

		if !ok {
			t.Error("expected ok to be true")
		}

		if val != "hello" {
			t.Errorf("expected val to be 'hello', got %q", val)
		}
	}
}
