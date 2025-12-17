package auth

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

// KerberosAuthenticator handles Kerberos/SPNEGO authentication
type KerberosAuthenticator struct {
	cfg        *config.KerberosConfig
	client     *client.Client
	targetHost string
}

// NewKerberosAuthenticator creates a new Kerberos authenticator
func NewKerberosAuthenticator(cfg *config.KerberosConfig, targetURL string) (*KerberosAuthenticator, error) {
	auth := &KerberosAuthenticator{
		cfg: cfg,
	}

	// Extract host from target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	auth.targetHost = parsedURL.Hostname()

	// Initialize Kerberos client
	if err := auth.initClient(); err != nil {
		return nil, err
	}

	return auth, nil
}

// initClient initializes the Kerberos client
func (a *KerberosAuthenticator) initClient() error {
	// Generate krb5.conf content
	krb5Conf := a.generateKrb5Config()

	// Parse the config
	krbCfg, err := krbconfig.NewFromString(krb5Conf)
	if err != nil {
		return fmt.Errorf("failed to parse krb5 config: %w", err)
	}

	// Load keytab
	kt, err := keytab.Load(a.cfg.KeytabPath)
	if err != nil {
		return fmt.Errorf("failed to load keytab %s: %w", a.cfg.KeytabPath, err)
	}

	// Parse principal
	username := a.cfg.Username
	realm := a.cfg.Realm
	if strings.Contains(username, "@") {
		parts := strings.SplitN(username, "@", 2)
		username = parts[0]
		if realm == "" {
			realm = parts[1]
		}
	}

	// Create client from keytab
	a.client = client.NewWithKeytab(username, realm, kt, krbCfg)

	// Login (get TGT)
	if err := a.client.Login(); err != nil {
		return fmt.Errorf("kerberos login failed: %w", err)
	}

	return nil
}

// generateKrb5Config generates a minimal krb5.conf
func (a *KerberosAuthenticator) generateKrb5Config() string {
	realm := a.cfg.Realm
	kdcServer := a.cfg.KDCServer
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

// ApplyToRequest adds SPNEGO authentication to the request
func (a *KerberosAuthenticator) ApplyToRequest(req *http.Request) error {
	// Get service principal name
	serviceName := a.cfg.ServiceName
	if serviceName == "" {
		serviceName = "HTTP"
	}
	spn := fmt.Sprintf("%s/%s", serviceName, a.targetHost)

	// Get SPNEGO token
	token, err := a.getSPNEGOToken(spn)
	if err != nil {
		return fmt.Errorf("failed to get SPNEGO token: %w", err)
	}

	// Add Authorization header
	req.Header.Set("Authorization", "Negotiate "+token)
	return nil
}

// getSPNEGOToken generates a SPNEGO token for the service
func (a *KerberosAuthenticator) getSPNEGOToken(spn string) (string, error) {
	spnegoClient := spnego.SPNEGOClient(a.client, spn)

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

// GetAuthorizationHeader returns the Authorization header value
func (a *KerberosAuthenticator) GetAuthorizationHeader() (string, error) {
	serviceName := a.cfg.ServiceName
	if serviceName == "" {
		serviceName = "HTTP"
	}
	spn := fmt.Sprintf("%s/%s", serviceName, a.targetHost)

	token, err := a.getSPNEGOToken(spn)
	if err != nil {
		return "", err
	}

	return "Negotiate " + token, nil
}

// Type returns the authentication type
func (a *KerberosAuthenticator) Type() string {
	return "kerberos"
}

// Close cleans up resources
func (a *KerberosAuthenticator) Close() {
	if a.client != nil {
		a.client.Destroy()
	}
}

// GetSPN returns the Service Principal Name for the target
func (a *KerberosAuthenticator) GetSPN() string {
	serviceName := a.cfg.ServiceName
	if serviceName == "" {
		serviceName = "HTTP"
	}
	return fmt.Sprintf("%s/%s@%s", serviceName, a.targetHost, a.cfg.Realm)
}
