package config_test

import (
	"crypto/rsa"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/github/go/config"
)

func TestFailsIfNotStructOrPointer(t *testing.T) {
	cfg := "hello"

	if err := config.Load(&cfg); err == nil {
		t.Fail()
	}

	if err := config.Load(cfg); err == nil {
		t.Fail()
	}
}

func TestSetsDefaultValues(t *testing.T) {
	cfg := &struct {
		NoTag    string
		String   string        `config:"a string"`
		Number   int           `config:"42"`
		Float    float64       `config:"3.14159"`
		Bool     bool          `config:"true"`
		Duration time.Duration `config:"3s"`
		Empty    string        `config:""`
	}{}

	if err := config.Load(cfg); err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.NoTag != "" {
		t.Error("NoTag not set to default")
	}

	if cfg.String != "a string" {
		t.Error("String not set to default")
	}

	if cfg.Number != 42 {
		t.Error("Number not set to default")
	}

	if cfg.Float != 3.14159 {
		t.Error("Float not set to default")
	}

	if !cfg.Bool {
		t.Error("Bool not set to default")
	}

	if cfg.Duration != time.Second*3 {
		t.Error("Duration not set to default")
	}

	if cfg.Empty != "" {
		t.Error("Empty not set to default")
	}
}

func TestLoader(t *testing.T) {
	cfg := &struct {
		String string `config:"default"`
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{"String": "fromloader"}))
	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.String != "fromloader" {
		t.Errorf("expected 'fromloader', got %q", cfg.String)
	}
}

func TestDefaultLoadChain(t *testing.T) {
	cfg := &struct {
		String string `config:"default"`
	}{}

	err := config.Load(cfg,
		newTestLoader("test1", map[string]string{"String": "fromloader1"}),
		newTestLoader("test2", map[string]string{"String": "fromloader2"}),
	)

	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.String != "fromloader1" {
		t.Errorf("expected 'fromloader1', got %q", cfg.String)
	}
}

func TestDefaultLoadChainPrecedence(t *testing.T) {
	cfg := &struct {
		Loader1 string `config:"default"`
		Loader2 string `config:"default"`
	}{}

	err := config.Load(cfg,
		newTestLoader("test1", map[string]string{"Loader1": "fromloader1"}),
		newTestLoader("test2", map[string]string{"Loader2": "fromloader2"}),
	)

	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.Loader1 != "fromloader1" {
		t.Errorf("expected 'fromloader1', got %q", cfg.Loader1)
	}

	if cfg.Loader2 != "fromloader2" {
		t.Errorf("expected 'fromloader2', got %q", cfg.Loader2)
	}
}

func TestExplicitLoadChain(t *testing.T) {
	cfg := &struct {
		String string `config:"default,test2"`
	}{}

	err := config.Load(cfg,
		newTestLoader("test1", map[string]string{"String": "fromloader1"}),
		newTestLoader("test2", map[string]string{"String": "fromloader2"}),
	)

	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.String != "fromloader2" {
		t.Errorf("expected 'fromloader2', got %q", cfg.String)
	}
}

func TestExplicitLoadChainSkipsEnv(t *testing.T) {
	cfg := &struct {
		String string `config:"default,test2"`
	}{}

	os.Setenv("String", "fromenv")
	defer os.Unsetenv("String")

	err := config.Load(cfg,
		newTestLoader("test1", map[string]string{"String": "fromloader1"}),
		newTestLoader("test2", map[string]string{"String": "fromloader2"}),
	)

	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.String != "fromloader2" {
		t.Errorf("expected 'fromloader2', got %q", cfg.String)
	}
}

func TestImplicitEnv(t *testing.T) {
	cfg := &struct {
		String string `config:"default"`
	}{}

	os.Setenv("STRING", "fromenv")
	defer os.Unsetenv("STRING")

	err := config.Load(cfg,
		newTestLoader("test1", map[string]string{"String": "fromloader1"}),
		newTestLoader("test2", map[string]string{"String": "fromloader2"}),
	)

	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.String != "fromenv" {
		t.Errorf("expected 'fromenv', got %q", cfg.String)
	}
}

func TestExplicitKey(t *testing.T) {
	cfg := &struct {
		String string `config:"default,test2=mykey"`
	}{}

	err := config.Load(cfg,
		newTestLoader("test1", map[string]string{"String": "fromloader1"}),
		newTestLoader("test2", map[string]string{"mykey": "fromloader2"}),
	)

	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.String != "fromloader2" {
		t.Errorf("expected 'fromloader2', got %q", cfg.String)
	}
}

func TestRequired(t *testing.T) {
	cfg := &struct {
		String string `config:",required"`
	}{}

	err := config.Load(cfg)
	if err == nil {
		t.Fatal("expected config to fail to load from missing value")
	}
}

func TestRequiredWithExplicitChain(t *testing.T) {
	cfg := &struct {
		String string `config:",test1,required"`
	}{}

	err := config.Load(cfg,
		newTestLoader("test1", map[string]string{"Absent": "fromloader1"}),
	)
	if err == nil {
		t.Fatal("expected config to fail to load from missing value")
	}
}

func TestNonZeroOverridesDeafult(t *testing.T) {
	cfg := &struct {
		String string `config:"default"`
	}{
		String: "nonzero",
	}

	if err := config.Load(cfg); err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.String != "nonzero" {
		t.Errorf("expected 'nonzero', got %q", cfg.String)
	}
}

func TestLoaderOverridesNonZero(t *testing.T) {
	cfg := &struct {
		String string `config:"default"`
	}{
		String: "nonzero",
	}

	err := config.Load(cfg, newTestLoader("test", map[string]string{"String": "fromloader"}))
	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.String != "fromloader" {
		t.Errorf("expected 'fromloader', got %q", cfg.String)
	}
}

func TestLoaderLookupError(t *testing.T) {
	cfg := &struct {
		String string `config:",required"`
	}{}

	loader := newTestLoader("test1", map[string]string{"Absent": "fromloader1"})
	loader.returnError = true

	err := config.Load(cfg, loader)
	if err == nil {
		t.Fatal("expected config to fail to load from lookup error")
	}
}

func TestLoaderLookupErrorWithExplicitChain(t *testing.T) {
	cfg := &struct {
		String string `config:",test1,required"`
	}{}

	loader := newTestLoader("test1", map[string]string{"Absent": "fromloader1"})
	loader.returnError = true

	err := config.Load(cfg, loader)
	if err == nil {
		t.Fatal("expected config to fail to load from lookup error")
	}
}

func TestBadTag(t *testing.T) {
	cfg := &struct {
		String string `config:",test1=foo=bar"`
	}{}

	loader := newTestLoader("test1", map[string]string{"Absent": "fromloader1"})
	loader.returnError = true

	err := config.Load(cfg, loader)
	if err == nil {
		t.Fatal("expected config to fail to load from lookup error")
	}
}

func TestExplicitLoaderNotCalledWhenNotGiven(t *testing.T) {
	cfg := &struct {
		String string `config:""`
	}{}

	loader := newTestLoader("test1", map[string]string{"String": "fromloader1"})
	loader.explicit = true

	err := config.Load(cfg, loader,
		newTestLoader("test2", map[string]string{"String": "fromloader2"}))
	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.String != "fromloader2" {
		t.Errorf("expected 'fromloader2', got %q", cfg.String)
	}
}

func TestLoaderNotProvided(t *testing.T) {
	cfg := &struct {
		String string `config:",test1"`
	}{}

	err := config.Load(cfg)
	if err == nil {
		t.Fatal("expected config to fail to load from lookup error")
	}
}

func TestNestedConfig(t *testing.T) {
	cfg := &struct {
		String string `config:"default"`
		Nested struct {
			NestedString string `config:"nestedDefault"`
		}
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{
		"String":       "fromloader",
		"NestedString": "fromnested",
	}))
	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	if cfg.String != "fromloader" {
		t.Errorf("expected 'fromloader', got %q", cfg.String)
	}

	if cfg.Nested.NestedString != "fromnested" {
		t.Errorf("expected 'fromnested', got %q", cfg.Nested.NestedString)
	}
}

func TestNestedConfigWithError(t *testing.T) {
	cfg := &struct {
		String string `config:"default"`
		Nested struct {
			NestedString string `config:"nestedDefault,foo=bar="`
		}
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{
		"String":       "fromloader",
		"NestedString": "fromnested",
	}))
	if err == nil {
		t.Fatal("expected error loading config")
	}
}

func TestNoParserForType(t *testing.T) {
	cfg := &struct {
		String string   `config:"default"`
		None   []string `config:""`
	}{}

	if err := config.Load(cfg); err == nil {
		t.Fail()
	}
}

func TestHandlesIntParseFailuresFromTag(t *testing.T) {
	cfg := &struct {
		Val int `config:"bogus"`
	}{}

	if err := config.Load(cfg); err == nil {
		t.Fail()
	}
}

func TestHandlesFloatParseFailuresFromTag(t *testing.T) {
	cfg := &struct {
		Val float64 `config:"bogus"`
	}{}

	if err := config.Load(cfg); err == nil {
		t.Fail()
	}
}

func TestHandlesBoolParseFailuresFromTag(t *testing.T) {
	cfg := &struct {
		Val bool `config:"bogus"`
	}{}

	if err := config.Load(cfg); err == nil {
		t.Fail()
	}
}

func TestHandlesDurationParseFailuresFromTag(t *testing.T) {
	cfg := &struct {
		Val time.Duration `config:"bogus"`
	}{}

	if err := config.Load(cfg); err == nil {
		t.Fail()
	}
}

func TestHandlesIntParseFailuresFromEnv(t *testing.T) {
	cfg := &struct {
		Val int `config:""`
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{"Val": "bogus"}))
	if err == nil {
		t.Fail()
	}
}

func TestHandlesFloatParseFailuresFromEnv(t *testing.T) {
	cfg := &struct {
		Val float64 `config:""`
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{"Val": "bogus"}))
	if err == nil {
		t.Fail()
	}
}

func TestHandlesBoolParseFailuresFromEnv(t *testing.T) {
	cfg := &struct {
		Val bool `config:""`
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{"Val": "bogus"}))
	if err == nil {
		t.Fail()
	}
}

func TestParseRSAPrivateKey(t *testing.T) {
	cfg := &struct {
		Key *rsa.PrivateKey `config:",nodefault"`
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{
		"Key": rsaPrivateKey,
	}))
	if err != nil {
		t.Fail()
	}

	if cfg.Key.Validate() != nil {
		t.Fail()
	}
}

func TestParseInvalidRSAPrivateKey(t *testing.T) {
	cfg := &struct {
		Key *rsa.PrivateKey `config:",nodefault"`
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{
		"Key": "bogus key",
	}))
	if err == nil {
		t.Fail()
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	cfg := &struct {
		Key *rsa.PublicKey `config:",nodefault"`
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{
		"Key": rsaPublicKey,
	}))

	if err != nil {
		t.Fail()
	}
	if cfg.Key == nil {
		t.Fail()
	}
}

func TestParseInvalidRSAPublicKey(t *testing.T) {
	cfg := &struct {
		Key *rsa.PublicKey `config:",nodefault"`
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{
		"Key": "bogus key",
	}))

	if err == nil {
		t.Fail()
	}
}

func TestUnparseableTypeFallsBackToDefault(t *testing.T) {
	cfg := &struct {
		T time.Duration `config:"2s"`
	}{}

	err := config.Load(cfg, newTestLoader("test", map[string]string{
		"T": "foo",
	}))

	if err != nil {
		t.Error("Load returned an error")
	}

	if cfg.T != time.Second*2 {
		t.Error("T did not fall back to the default value")
	}
}

const (
	rsaPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`
	rsaPublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsu9rlVn2fjYySkNnEgb7
4qoF8VDgzN95HVmLDfuAkAzaRiWMHHBTK2CzEDU+27As2fA0Q1LBkoxo21zyvB9K
fLtZsM4mlj8a4B1v3pXc0+oNz1bh9gn95yLMs+KcDAqniHOpxcf2lOD4tGFPCZ7a
1jJUzlAzAKZ7Ojh/ff2lD27JidwdSuZKugryawWJkwe2qGn8heNJdzqP2AVQOGfe
qGfALxuUbjf+i1O0ogYIMEWogOeaP1RP6/82iOibAjdLHJ/YubPmh+YKKCqkOtLj
uRHOi5eWBZUhyDppvq6KPt11Baj9ClstnY27R2gfLceHt93cbfGgvlsvq2bn4YH/
yRWK0WdqVivwkY+eMrsh5WKuuahcVd7qYXBET/YqwMLvF3v1m0Ru1dEoWYnLSYO9
FqYc/WpzmPFTABg4KIykXXPBAz4FlOscods2U26TA57Qjnaw5THkutPa8fiHvy4C
VZaZ/4W82QcD5NN3LOR5wi5zaL0tilbKoxvHQ+kc4s8lB2T5IXsApyttMqNaBFRT
DzSa9KjYxoCvXUOX+afGbLEo7cqTezAMQQ3z+dCXEUsEiVIV2f7sfW+vK9DPe2pY
/jHIMFcz0ZmDqu3bpjMkVgM+U5js+Jo8hecPRRUltzV27/6qMwqZ2+7lyzwBROZf
GoZLb6btVT7idhS7F1xurdMCAwEAAQ==
-----END RSA PUBLIC KEY-----
`
)

type testLoader struct {
	m           map[string]string
	name        string
	returnError bool
	explicit    bool
}

func newTestLoader(name string, m map[string]string) *testLoader {
	return &testLoader{m: m, name: name}
}

func (m *testLoader) Lookup(key string) (string, bool, error) {
	if m.returnError {
		return "", false, errors.New("loader lookup error")
	}
	val, ok := m.m[key]
	return val, ok, nil
}

func (m *testLoader) Name() string {
	return m.name
}

func (m *testLoader) Explicit() bool {
	return m.explicit
}
