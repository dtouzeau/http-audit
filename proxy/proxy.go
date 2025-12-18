package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"http-audit/config"
)

// ProxyConfig holds proxy configuration for HTTP transport
type ProxyConfig struct {
	enabled  bool
	proxyURL *url.URL
	auth     *ProxyAuth
}

// ProxyAuth holds proxy authentication credentials
type ProxyAuth struct {
	authType string
	username string
	password string
}

// NewProxyConfig creates a new proxy configuration from config
func NewProxyConfig(cfg *config.ProxyConfig) (*ProxyConfig, error) {
	if !cfg.Enabled {
		return &ProxyConfig{enabled: false}, nil
	}

	proxyURL, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	pc := &ProxyConfig{
		enabled:  true,
		proxyURL: proxyURL,
	}

	// Configure authentication if provided
	if cfg.Auth.Type == "basic" && cfg.Auth.Username != "" {
		pc.auth = &ProxyAuth{
			authType: "basic",
			username: cfg.Auth.Username,
			password: cfg.Auth.Password,
		}
	}

	return pc, nil
}

// IsEnabled returns whether proxy is enabled
func (p *ProxyConfig) IsEnabled() bool {
	return p.enabled
}

// GetProxyURL returns the proxy URL
func (p *ProxyConfig) GetProxyURL() *url.URL {
	return p.proxyURL
}

// GetProxyFunc returns a function suitable for http.Transport.Proxy
func (p *ProxyConfig) GetProxyFunc() func(*http.Request) (*url.URL, error) {
	if !p.enabled {
		return nil
	}

	return func(req *http.Request) (*url.URL, error) {
		return p.proxyURL, nil
	}
}

// ApplyToTransport configures proxy settings on an HTTP transport
func (p *ProxyConfig) ApplyToTransport(transport *http.Transport) {
	if !p.enabled {
		return
	}

	transport.Proxy = p.GetProxyFunc()
}

// ApplyToRequest adds proxy authentication headers to a request
func (p *ProxyConfig) ApplyToRequest(req *http.Request) {
	if !p.enabled || p.auth == nil {
		return
	}

	if p.auth.authType == "basic" {
		credentials := p.auth.username + ":" + p.auth.password
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		req.Header.Set("Proxy-Authorization", "Basic "+encoded)
	}
}

// GetProxyAuthHeader returns the Proxy-Authorization header value
func (p *ProxyConfig) GetProxyAuthHeader() string {
	if p.auth == nil {
		return ""
	}

	if p.auth.authType == "basic" {
		credentials := p.auth.username + ":" + p.auth.password
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		return "Basic " + encoded
	}

	return ""
}

// ProxyInfo contains information about the proxy configuration
type ProxyInfo struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url,omitempty"`
	AuthType string `json:"auth_type,omitempty"`
	Username string `json:"username,omitempty"`
}

// GetInfo returns proxy configuration information (without password)
func (p *ProxyConfig) GetInfo() ProxyInfo {
	info := ProxyInfo{
		Enabled: p.enabled,
	}

	if p.enabled && p.proxyURL != nil {
		info.URL = p.proxyURL.String()
	}

	if p.auth != nil {
		info.AuthType = p.auth.authType
		info.Username = p.auth.username
	}

	return info
}

// GetHost returns the proxy hostname
func (p *ProxyConfig) GetHost() string {
	if p.proxyURL == nil {
		return ""
	}
	return p.proxyURL.Hostname()
}

// GetPort returns the proxy port
func (p *ProxyConfig) GetPort() string {
	if p.proxyURL == nil {
		return ""
	}
	port := p.proxyURL.Port()
	if port == "" {
		if p.proxyURL.Scheme == "https" {
			return "443"
		}
		return "8080"
	}
	return port
}

// GetAuthType returns the authentication type
func (p *ProxyConfig) GetAuthType() string {
	if p.auth == nil {
		return "none"
	}
	return p.auth.authType
}
