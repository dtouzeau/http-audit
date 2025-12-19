package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"http-audit/config"

	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// ProxyConfig holds proxy configuration for HTTP transport
type ProxyConfig struct {
	enabled   bool
	proxyURL  *url.URL
	auth      *ProxyAuth
	krbClient *client.Client
	krbConfig *config.ProxyKerberosConfig
}

// ProxyAuth holds proxy authentication credentials
type ProxyAuth struct {
	authType string
	username string
	password string
}

// NewProxyConfig creates a new proxy configuration from config
// Note: For kerberos auth with generate_keytab=true, call InitKerberosAuth() after keytab generation
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
	switch cfg.Auth.Type {
	case "basic":
		if cfg.Auth.Username != "" {
			pc.auth = &ProxyAuth{
				authType: "basic",
				username: cfg.Auth.Username,
				password: cfg.Auth.Password,
			}
		}
	case "kerberos":
		pc.auth = &ProxyAuth{
			authType: "kerberos",
		}
		pc.krbConfig = &cfg.Auth.Kerberos
		// If keytab needs to be generated, delay kerberos client initialization
		// Call InitKerberosAuth() after keytab is generated
		if !cfg.Auth.Kerberos.GenerateKeytab {
			if err := pc.initKerberosClient(); err != nil {
				return nil, fmt.Errorf("kerberos initialization failed: %w", err)
			}
		}
	}

	return pc, nil
}

// InitKerberosAuth initializes the Kerberos client after keytab is generated
// This should be called after keytab generation when GenerateKeytab is true
func (p *ProxyConfig) InitKerberosAuth() error {
	if p.auth == nil || p.auth.authType != "kerberos" {
		return nil
	}
	if p.krbClient != nil {
		return nil // Already initialized
	}
	return p.initKerberosClient()
}

// NeedsKerberosInit returns true if kerberos auth needs initialization
func (p *ProxyConfig) NeedsKerberosInit() bool {
	return p.auth != nil && p.auth.authType == "kerberos" && p.krbClient == nil && p.krbConfig != nil
}

// GetKerberosConfig returns the kerberos config for keytab generation
func (p *ProxyConfig) GetKerberosConfig() *config.ProxyKerberosConfig {
	return p.krbConfig
}

// initKerberosClient initializes the Kerberos client for proxy auth
func (p *ProxyConfig) initKerberosClient() error {
	if p.krbConfig == nil {
		return fmt.Errorf("kerberos config is nil")
	}

	// Generate krb5.conf content
	krb5Conf := p.generateKrb5Config()

	// Parse the config
	krbCfg, err := krbconfig.NewFromString(krb5Conf)
	if err != nil {
		return fmt.Errorf("failed to parse krb5 config: %w", err)
	}

	// Load keytab
	kt, err := keytab.Load(p.krbConfig.KeytabPath)
	if err != nil {
		return fmt.Errorf("failed to load keytab %s: %w", p.krbConfig.KeytabPath, err)
	}

	// Parse principal
	username := p.krbConfig.Username
	realm := p.krbConfig.Realm
	if strings.Contains(username, "@") {
		parts := strings.SplitN(username, "@", 2)
		username = parts[0]
		if realm == "" {
			realm = parts[1]
		}
	}

	// Create client from keytab
	p.krbClient = client.NewWithKeytab(username, realm, kt, krbCfg)

	// Login (get TGT)
	if err := p.krbClient.Login(); err != nil {
		return fmt.Errorf("kerberos login failed: %w", err)
	}

	return nil
}

// generateKrb5Config generates a minimal krb5.conf for proxy kerberos
func (p *ProxyConfig) generateKrb5Config() string {
	realm := p.krbConfig.Realm
	kdcServer := p.krbConfig.KDCServer
	if kdcServer == "" {
		kdcServer = "kdc." + strings.ToLower(realm)
	}

	return fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    %s = {
        kdc = %s
        admin_server = %s
    }

[domain_realm]
    .%s = %s
    %s = %s
`, realm, realm, kdcServer, kdcServer,
		strings.ToLower(realm), realm,
		strings.ToLower(realm), realm)
}

// getSPNEGOToken generates a SPNEGO token for the proxy
func (p *ProxyConfig) getSPNEGOToken() (string, error) {
	if p.krbClient == nil {
		return "", fmt.Errorf("kerberos client not initialized")
	}

	serviceName := p.krbConfig.ServiceName
	if serviceName == "" {
		serviceName = "HTTP"
	}
	spn := fmt.Sprintf("%s/%s", serviceName, p.proxyURL.Hostname())

	spnegoClient := spnego.SPNEGOClient(p.krbClient, spn)

	err := spnegoClient.AcquireCred()
	if err != nil {
		return "", fmt.Errorf("failed to acquire credentials: %w", err)
	}

	token, err := spnegoClient.InitSecContext()
	if err != nil {
		return "", fmt.Errorf("failed to init security context: %w", err)
	}

	tokenBytes, err := token.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

// Close cleans up resources
func (p *ProxyConfig) Close() {
	if p.krbClient != nil {
		p.krbClient.Destroy()
	}
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
func (p *ProxyConfig) ApplyToRequest(req *http.Request) error {
	if !p.enabled || p.auth == nil {
		return nil
	}

	switch p.auth.authType {
	case "basic":
		credentials := p.auth.username + ":" + p.auth.password
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		req.Header.Set("Proxy-Authorization", "Basic "+encoded)
	case "kerberos":
		token, err := p.getSPNEGOToken()
		if err != nil {
			return fmt.Errorf("failed to get SPNEGO token for proxy: %w", err)
		}
		req.Header.Set("Proxy-Authorization", "Negotiate "+token)
	}
	return nil
}

// GetProxyAuthHeader returns the Proxy-Authorization header value
func (p *ProxyConfig) GetProxyAuthHeader() (string, error) {
	if p.auth == nil {
		return "", nil
	}

	switch p.auth.authType {
	case "basic":
		credentials := p.auth.username + ":" + p.auth.password
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		return "Basic " + encoded, nil
	case "kerberos":
		token, err := p.getSPNEGOToken()
		if err != nil {
			return "", err
		}
		return "Negotiate " + token, nil
	}

	return "", nil
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
