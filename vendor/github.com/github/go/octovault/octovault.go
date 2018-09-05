package octovault

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
)

const (
	defaultSocket   = "/var/lib/octovault/octovault.sock"
	clientUserAgent = "go-octovault-client"
)

// Config configures an Octovault client. If the VaultToken is empty,
// it will be pulled from the VAULT_TOKEN environment variable. If
// VaultSocket is empty, the default vault socket path will be used.
type Config struct {
	VaultToken  string
	VaultSocket string
}

func (c Config) token() string {
	if len(c.VaultToken) == 0 {
		return os.Getenv("VAULT_TOKEN")
	}
	return c.VaultToken
}

func (c Config) socket() string {
	if len(c.VaultSocket) == 0 {
		return defaultSocket
	}
	return c.VaultSocket
}

// Octovault is an octovault client
type Octovault struct {
	client *http.Client
	token  string
}

// Secrets is a map of secret keys to values
type Secrets map[string]string

// New creates a new octovault client
func New(cfg Config) *Octovault {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", cfg.socket())
			},
		},
	}

	return &Octovault{
		client: c,
		token:  cfg.token(),
	}
}

// GetSecrets gets all secrets for an application in an environment
func (o *Octovault) GetSecrets(application, environment string) (Secrets, error) {
	url := fmt.Sprintf("http://octovault/v1/apps/%s/%s", application, environment)
	return o.get(url)
}

// GetSecret gets a single secret for an application in an environment
func (o *Octovault) GetSecret(application, environment, key string) (string, error) {
	url := fmt.Sprintf("http://octovault/v1/apps/%s/%s/%s", application, environment, key)
	secrets, err := o.get(url)
	if err != nil {
		return "", err
	}

	return secrets[key], nil
}

// GetRoleSecrets get all secrets for a gh_app and gh_role
func (o *Octovault) GetRoleSecrets(application, role, environment string) (Secrets, error) {
	url := fmt.Sprintf("http://octovault/v1/gh_app/%s/%s/%s", application, role, environment)
	return o.get(url)
}

// GetRoleSecret get one secret for a gh-app and gh_role
func (o *Octovault) GetRoleSecret(application, role, environment, key string) (string, error) {
	url := fmt.Sprintf("http://octovault/v1/gh_app/%s/%s/%s/%s", application, role, environment, key)
	secrets, err := o.get(url)
	if err != nil {
		return "", err
	}

	return secrets[key], nil
}

func (o *Octovault) get(url string) (Secrets, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Vault-Token", o.token)
	req.Header.Set("User-Agent", clientUserAgent)

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid status %d", resp.StatusCode)
	}

	var secrets Secrets
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, err
	}

	return secrets, nil
}
