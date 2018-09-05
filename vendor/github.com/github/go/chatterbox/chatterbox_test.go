package chatterbox

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	_, err := New("foo", "http://example.local")
	assert.Nil(t, err)

	_, err = New("foo", "")
	assert.NotNil(t, err)

	_, err = New("foo", "%x") // invalid url
	assert.NotNil(t, err)

	_, err = New("", "http://example.local")
	assert.NotNil(t, err)
}

func TestMessageTypeEncode(t *testing.T) {
	m := messageType{Text: "foo bar"}
	// Encode returns an io.Reader, so convert it to a string so we can assert
	msg := m.Encode()

	buf := new(bytes.Buffer)
	buf.ReadFrom(msg)
	s := buf.String()

	assert.Equal(t, s, "{\"text\":\"foo bar\"}\n", "Message encodes correctly")
}

func TestClientSay(t *testing.T) {
	var called bool
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			called = true
			assert.Equal(t, r.URL.Path, "/topics/test-room")
			assert.Contains(t, r.Header.Get("Authorization"), "Basic")
		}))
	defer s.Close()

	chatter, err := New("token", s.URL) // uses the test server URL as a base
	assert.Nil(t, err)
	err = chatter.Say("test-room", "ohai!")
	assert.Nil(t, err)
	assert.True(t, called)
	assert.Equal(t, chatter.parsedURL.String(), s.URL, "original URL wasn't modified")

	chatter, err = New("token", "foo.bar")
	assert.Nil(t, err)
	err = chatter.Say("test-room", "ohai!")
	assert.NotNil(t, err)
}

func TestSay(t *testing.T) {
	var called bool
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			called = true
			assert.Equal(t, r.URL.Path, "/topics/test-room")
			assert.Contains(t, r.Header.Get("Authorization"), "Basic")
		}))
	defer s.Close()

	err := Say("token", s.URL, "test-room", "ohai!")
	assert.Nil(t, err)
	assert.True(t, called)

	err = Say("token", "foo.bar", "test-room", "ohai!")
	assert.NotNil(t, err)

	err = Say("token", "%x", "test-room", "ohai!")
	assert.NotNil(t, err)
}

func ExampleSay() {
	err := Say("token", "https://chatterbox.githubapp.com", "dumping-ground", "Hello, world!")
	if err != nil {
		log.Fatalf("Error sending to chatterbox: %v", err)
	}
}

func ExampleClient_Say() {
	client, err := New("token", "https://chatterbox.githubapp.com")
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	err = client.Say("dumping-ground", "Hello, world!")
	if err != nil {
		log.Fatalf("Error sending to chatterbox: %v", err)
	}
}

func ExampleNew() {
	client, err := New("mytoken", "https://chatterbox.githubapp.com")
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}
	_ = client
}
