// Package chatterbox sends messages to chatterbox, GitHub's API for sending
// messages into chat.
//
// To send a message, without creating a Client, use Say:
//
//     err := chatterbox.Say(token, url, "my topic", "hello, world!")
//     ...
//
//
// To create a client:
//
//     client := chatterbox.New(token, url)
//     err := client.Say("my topic", "hello, world!")
//     ...
//
package chatterbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Client is an authenticated client used for sending messages to chatterbox
type Client struct {
	token      string
	httpClient *http.Client
	parsedURL  *url.URL
}

// New returns a new chatterbox.Client which can be used for sending things
// to chatterbox via client.Say(...)
func New(token string, chatterboxURL string) (*Client, error) {
	if token == "" {
		return nil, errors.New("token must not be empty")
	}
	if chatterboxURL == "" {
		return nil, errors.New("chatterboxURL must not be empty")
	}

	parsedURL, err := url.Parse(chatterboxURL)
	if err != nil {
		return nil, err
	}

	return &Client{
		token:      token,
		httpClient: &http.Client{},
		parsedURL:  parsedURL}, nil
}

// Say posts a message to the given topic. Say returns an error or nil if
// everything succeeded.
func (c *Client) Say(topic string, message string) error {
	var r url.URL
	// copy parsedURL object and create a local request url from the copy
	r = *c.parsedURL
	r.Path = fmt.Sprintf("/topics/%s", url.QueryEscape(topic))

	m := &messageType{Text: message}
	return c.post(r.String(), m.Encode())
}

// post posts the message to chatterbox
func (c *Client) post(requestURL string, data io.Reader) error {
	req, err := http.NewRequest("POST", requestURL, data)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.token, "X")
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Say posts a message to the given topic, but without requiring a new
// chatterbox.Client to be created. Returns an error or nil if everything
// succeeded.
func Say(token string, url string, topic string, message string) error {
	c, err := New(token, url)
	if err != nil {
		return err
	}

	return c.Say(topic, message)
}

// messageType is an internally used structure for serializing the message to JSON
type messageType struct {
	Text string `json:"text"`
}

// Encode coverts the messageType structure into a JSON representation and
// returns an io.Reader representation for use by http.Request
func (m *messageType) Encode() io.Reader {
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(m)
	return b
}
