package auth

import (
	"encoding/base64"
	"net/http"

	"http-audit/config"
)

// BasicAuthenticator handles HTTP Basic authentication
type BasicAuthenticator struct {
	username string
	password string
}

// NewBasicAuthenticator creates a new Basic authenticator from config
func NewBasicAuthenticator(cfg *config.BasicAuth) *BasicAuthenticator {
	return &BasicAuthenticator{
		username: cfg.Username,
		password: cfg.Password,
	}
}

// ApplyToRequest adds Basic authentication header to the request
func (a *BasicAuthenticator) ApplyToRequest(req *http.Request) {
	if a.username == "" {
		return
	}
	req.SetBasicAuth(a.username, a.password)
}

// GetAuthorizationHeader returns the Authorization header value
func (a *BasicAuthenticator) GetAuthorizationHeader() string {
	if a.username == "" {
		return ""
	}
	credentials := a.username + ":" + a.password
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	return "Basic " + encoded
}

// Type returns the authentication type
func (a *BasicAuthenticator) Type() string {
	return "basic"
}
