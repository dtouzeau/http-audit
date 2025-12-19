package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"
)

// Duration is a wrapper for time.Duration that supports JSON unmarshaling from strings
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", value, err)
		}
	case map[string]interface{}:
		// Handle object format: {"Duration": 10000000000}
		if dur, ok := value["Duration"]; ok {
			switch durVal := dur.(type) {
			case float64:
				d.Duration = time.Duration(durVal)
			case string:
				var err error
				d.Duration, err = time.ParseDuration(durVal)
				if err != nil {
					return fmt.Errorf("invalid duration %q: %w", durVal, err)
				}
			default:
				return fmt.Errorf("invalid Duration field type: %T", dur)
			}
		} else {
			return fmt.Errorf("missing Duration field in object")
		}
	default:
		return fmt.Errorf("invalid duration type: %T", v)
	}
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

// Config represents the complete audit configuration
type Config struct {
	Target       TargetConfig       `json:"target"`
	Network      NetworkConfig      `json:"network"`
	DNS          DNSConfig          `json:"dns"`
	Proxy        ProxyConfig        `json:"proxy"`
	Auth         AuthConfig         `json:"auth"`
	SSL          SSLConfig          `json:"ssl"`
	HTTP         HTTPConfig         `json:"http"`
	PageAnalysis PageAnalysisConfig `json:"page_analysis"`
	Output       OutputConfig       `json:"output"`
}

// TargetConfig defines the target URL and request parameters
type TargetConfig struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// NetworkConfig defines network-level settings
type NetworkConfig struct {
	Interface      string   `json:"interface"`
	TimeoutConnect Duration `json:"timeout_connect"`
	TimeoutRead    Duration `json:"timeout_read"`
	TimeoutTotal   Duration `json:"timeout_total"`
}

// DNSConfig defines DNS resolution settings
type DNSConfig struct {
	Enabled        bool     `json:"enabled"`
	Servers        []string `json:"servers"`
	ExpectIPs      []string `json:"expect_ips"`
	Timeout        Duration `json:"timeout"`
	TestAllServers bool     `json:"test_all_servers"`
}

// ProxyConfig defines HTTP proxy settings
type ProxyConfig struct {
	Enabled bool            `json:"enabled"`
	URL     string          `json:"url"`
	Auth    ProxyAuthConfig `json:"auth"`
}

// ProxyAuthConfig defines proxy authentication
type ProxyAuthConfig struct {
	Type     string              `json:"type"` // none, basic, kerberos
	Username string              `json:"username"`
	Password string              `json:"password"`
	Kerberos ProxyKerberosConfig `json:"kerberos,omitempty"`
}

// ProxyKerberosConfig defines Kerberos authentication settings for proxy
type ProxyKerberosConfig struct {
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	KDCServer      string `json:"kdc_server,omitempty"`
	Realm          string `json:"realm,omitempty"`
	KeytabPath     string `json:"keytab_path,omitempty"`
	GenerateKeytab bool   `json:"generate_keytab,omitempty"`
	ServiceName    string `json:"service_name,omitempty"`
}

// AuthConfig defines target authentication settings
type AuthConfig struct {
	Type     string         `json:"type"` // none, basic, kerberos
	Basic    BasicAuth      `json:"basic"`
	Kerberos KerberosConfig `json:"kerberos"`
}

// BasicAuth defines basic authentication credentials
type BasicAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// KerberosConfig defines Kerberos authentication settings
type KerberosConfig struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	KDCServer      string `json:"kdc_server"`
	Realm          string `json:"realm"`
	KeytabPath     string `json:"keytab_path"`
	GenerateKeytab bool   `json:"generate_keytab"`
	ServiceName    string `json:"service_name"` // Usually "HTTP"
}

// SSLConfig defines SSL/TLS verification settings
type SSLConfig struct {
	Verify         bool   `json:"verify"`
	CheckProtocols bool   `json:"check_protocols"`
	CheckCiphers   bool   `json:"check_ciphers"`
	MinVersion     string `json:"min_version"` // TLS1.0, TLS1.1, TLS1.2, TLS1.3
}

// HTTPConfig defines HTTP client behavior
type HTTPConfig struct {
	UserAgent       string `json:"user_agent"`
	FollowRedirects bool   `json:"follow_redirects"`
	MaxRedirects    int    `json:"max_redirects"`
	AcceptLanguage  string `json:"accept_language"`
	AcceptEncoding  string `json:"accept_encoding"`
	Connection      string `json:"connection"`
	Referer         string `json:"referer"`
	XForwardedFor   string `json:"x_forwarded_for"`
}

// PageAnalysisConfig defines page resource analysis settings
type PageAnalysisConfig struct {
	Enabled     bool     `json:"enabled"`
	Timeout     Duration `json:"timeout"`
	MaxRequests int      `json:"max_requests"`
	Types       []string `json:"types"` // css, js, image, font, link
}

// OutputConfig defines report output paths
type OutputConfig struct {
	HTMLPath   string `json:"html_path"`
	JSONPath   string `json:"json_path"`
	ChartJSURL string `json:"chartjs_url"`
}

// Load reads and parses a configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	cfg.SetDefaults()
	return &cfg, nil
}

// SetDefaults applies default values for unset fields
func (c *Config) SetDefaults() {
	if c.Target.Method == "" {
		c.Target.Method = "GET"
	}
	if c.Network.TimeoutConnect.Duration == 0 {
		c.Network.TimeoutConnect.Duration = 10 * time.Second
	}
	if c.Network.TimeoutRead.Duration == 0 {
		c.Network.TimeoutRead.Duration = 30 * time.Second
	}
	if c.Network.TimeoutTotal.Duration == 0 {
		c.Network.TimeoutTotal.Duration = 60 * time.Second
	}
	if c.DNS.Timeout.Duration == 0 {
		c.DNS.Timeout.Duration = 2 * time.Second // Low timeout for fast DNS testing
	}
	if c.HTTP.UserAgent == "" {
		c.HTTP.UserAgent = "http-audit/1.0"
	}
	if c.HTTP.MaxRedirects == 0 {
		c.HTTP.MaxRedirects = 10
	}
	if c.HTTP.AcceptLanguage == "" {
		c.HTTP.AcceptLanguage = "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3"
	}
	if c.HTTP.AcceptEncoding == "" {
		c.HTTP.AcceptEncoding = "gzip, deflate, br"
	}
	if c.HTTP.Connection == "" {
		c.HTTP.Connection = "keep-alive"
	}
	if c.SSL.MinVersion == "" {
		c.SSL.MinVersion = "TLS1.2"
	}
	if c.Auth.Kerberos.ServiceName == "" {
		c.Auth.Kerberos.ServiceName = "HTTP"
	}
	// PageAnalysis defaults
	if c.PageAnalysis.Timeout.Duration == 0 {
		c.PageAnalysis.Timeout.Duration = 5 * time.Second
	}
	if c.PageAnalysis.MaxRequests == 0 {
		c.PageAnalysis.MaxRequests = 50
	}
	if len(c.PageAnalysis.Types) == 0 {
		c.PageAnalysis.Types = []string{"css", "js", "image", "font", "link"}
	}
	if c.Output.HTMLPath == "" {
		c.Output.HTMLPath = "./report.html"
	}
	if c.Output.JSONPath == "" {
		c.Output.JSONPath = "./report.json"
	}
	if c.Output.ChartJSURL == "" {
		c.Output.ChartJSURL = "https://cdn.jsdelivr.net/npm/chart.js"
	}
}

// Validate checks the configuration for errors
func (c *Config) Validate() error {
	if c.Target.URL == "" {
		return fmt.Errorf("target.url is required")
	}

	parsedURL, err := url.Parse(c.Target.URL)
	if err != nil {
		return fmt.Errorf("invalid target.url: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("target.url must use http or https scheme")
	}
	if parsedURL.Host == "" {
		return fmt.Errorf("target.url must have a host")
	}

	if c.Proxy.Enabled && c.Proxy.URL == "" {
		return fmt.Errorf("proxy.url is required when proxy is enabled")
	}

	if c.Proxy.Enabled && c.Proxy.URL != "" {
		if _, err := url.Parse(c.Proxy.URL); err != nil {
			return fmt.Errorf("invalid proxy.url: %w", err)
		}
	}

	switch c.Auth.Type {
	case "", "none":
		// OK
	case "basic":
		if c.Auth.Basic.Username == "" {
			return fmt.Errorf("auth.basic.username is required for basic auth")
		}
	case "kerberos":
		if c.Auth.Kerberos.Realm == "" {
			return fmt.Errorf("auth.kerberos.realm is required for kerberos auth")
		}
		if c.Auth.Kerberos.GenerateKeytab {
			if c.Auth.Kerberos.Username == "" {
				return fmt.Errorf("auth.kerberos.username is required to generate keytab")
			}
			if c.Auth.Kerberos.Password == "" {
				return fmt.Errorf("auth.kerberos.password is required to generate keytab")
			}
			if c.Auth.Kerberos.KDCServer == "" {
				return fmt.Errorf("auth.kerberos.kdc_server is required to generate keytab")
			}
			if c.Auth.Kerberos.KeytabPath == "" {
				return fmt.Errorf("auth.kerberos.keytab_path is required to generate keytab")
			}
		} else {
			if c.Auth.Kerberos.KeytabPath == "" {
				return fmt.Errorf("auth.kerberos.keytab_path is required for kerberos auth")
			}
		}
	default:
		return fmt.Errorf("invalid auth.type: %s (must be none, basic, or kerberos)", c.Auth.Type)
	}

	switch c.SSL.MinVersion {
	case "", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3":
		// OK
	default:
		return fmt.Errorf("invalid ssl.min_version: %s", c.SSL.MinVersion)
	}

	return nil
}

// GetTargetHost returns the host from the target URL
func (c *Config) GetTargetHost() string {
	parsedURL, _ := url.Parse(c.Target.URL)
	return parsedURL.Hostname()
}

// GetTargetPort returns the port from the target URL (default 80/443)
func (c *Config) GetTargetPort() string {
	parsedURL, _ := url.Parse(c.Target.URL)
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return port
}

// IsHTTPS returns true if the target uses HTTPS
func (c *Config) IsHTTPS() bool {
	parsedURL, _ := url.Parse(c.Target.URL)
	return parsedURL.Scheme == "https"
}
