package audit

import (
	"context"
	"fmt"
	"time"

	"http-audit/auth"
	"http-audit/config"
	"http-audit/network"
	"http-audit/proxy"
)

// Auditor orchestrates the complete HTTP audit process
type Auditor struct {
	cfg               *config.Config
	interfaceResolver *network.InterfaceResolver
	proxyConfig       *proxy.ProxyConfig
	dnsAuditor        *DNSAuditor
	sslAuditor        *SSLAuditor
	httpAuditor       *HTTPAuditor
	basicAuth         *auth.BasicAuthenticator
	kerberosAuth      *auth.KerberosAuthenticator
}

// NewAuditor creates a new audit orchestrator
func NewAuditor(cfg *config.Config) (*Auditor, error) {
	a := &Auditor{cfg: cfg}

	// Initialize network interface resolver
	if cfg.Network.Interface != "" {
		resolver, err := network.NewInterfaceResolver(cfg.Network.Interface)
		if err != nil {
			return nil, fmt.Errorf("interface setup failed: %w", err)
		}
		a.interfaceResolver = resolver
	}

	// Initialize proxy configuration
	proxyConfig, err := proxy.NewProxyConfig(&cfg.Proxy)
	if err != nil {
		return nil, fmt.Errorf("proxy setup failed: %w", err)
	}
	a.proxyConfig = proxyConfig

	// Initialize auditors
	a.dnsAuditor = NewDNSAuditor(cfg)
	a.sslAuditor = NewSSLAuditor(cfg, a.interfaceResolver)
	a.httpAuditor = NewHTTPAuditor(cfg, a.interfaceResolver, proxyConfig)

	// Initialize authentication
	switch cfg.Auth.Type {
	case "basic":
		a.basicAuth = auth.NewBasicAuthenticator(&cfg.Auth.Basic)
		a.httpAuditor.SetBasicAuth(a.basicAuth)
	case "kerberos":
		// Kerberos auth will be initialized after keytab generation
	}

	return a, nil
}

// Run executes the complete audit process
func (a *Auditor) Run(ctx context.Context) *Result {
	result := NewResult(a.cfg.Target.URL)
	overallStart := time.Now()

	// Step 1: Generate keytab if needed
	if a.cfg.Auth.Type == "kerberos" && a.cfg.Auth.Kerberos.GenerateKeytab {
		fmt.Println("Generating Kerberos keytab...")
		keytabGen := auth.NewKeytabGenerator(&a.cfg.Auth.Kerberos)
		authKeytabResult := keytabGen.Generate()

		// Convert auth.KeytabResult to audit.KeytabResult
		result.Keytab = &KeytabResult{
			Success:     authKeytabResult.Success,
			Generated:   authKeytabResult.Generated,
			Path:        authKeytabResult.Path,
			Principal:   authKeytabResult.Principal,
			Error:       authKeytabResult.Error,
			Duration:    Duration{authKeytabResult.Duration},
			GeneratedAt: authKeytabResult.GeneratedAt,
		}

		if !result.Keytab.Success {
			fmt.Printf("Keytab generation failed: %s\n", result.Keytab.Error)
			result.SetError(fmt.Errorf("keytab generation failed: %s", result.Keytab.Error))
			result.CalculateSummary()
			return result
		}
		fmt.Printf("Keytab generated successfully at %s\n", result.Keytab.Path)
	}

	// Initialize Kerberos auth after keytab is ready
	if a.cfg.Auth.Type == "kerberos" {
		kerberosAuth, err := auth.NewKerberosAuthenticator(&a.cfg.Auth.Kerberos, a.cfg.Target.URL)
		if err != nil {
			result.SetError(fmt.Errorf("kerberos initialization failed: %w", err))
			result.CalculateSummary()
			return result
		}
		a.kerberosAuth = kerberosAuth
		a.httpAuditor.SetKerberosAuth(kerberosAuth)
		defer kerberosAuth.Close()
	}

	// Step 2: DNS Resolution
	if a.cfg.DNS.Enabled {
		fmt.Println("Performing DNS resolution...")
		dnsCtx, dnsCancel := context.WithTimeout(ctx, a.cfg.Network.TimeoutConnect.Duration)
		result.DNS = a.dnsAuditor.Audit(dnsCtx)
		dnsCancel()

		result.Timings.DNSLookup = result.DNS.Duration

		if result.DNS.Success {
			fmt.Printf("DNS resolved %s to %v in %v\n",
				result.DNS.Hostname, result.DNS.ResolvedIPs, result.DNS.Duration.Duration)
		} else {
			fmt.Printf("DNS resolution failed: %s\n", result.DNS.Error)
		}
	}

	// Step 3: SSL/TLS Analysis (only for HTTPS)
	if a.cfg.IsHTTPS() {
		fmt.Println("Analyzing SSL/TLS...")
		sslCtx, sslCancel := context.WithTimeout(ctx, a.cfg.Network.TimeoutConnect.Duration*2)
		result.SSL = a.sslAuditor.Audit(sslCtx)
		sslCancel()

		result.Timings.TLSHandshake = result.SSL.Duration

		if result.SSL.Success {
			fmt.Printf("SSL connected with %s using %s\n", result.SSL.Protocol, result.SSL.CipherSuite)
			if len(result.SSL.Certificates) > 0 {
				cert := result.SSL.Certificates[0]
				fmt.Printf("Certificate: %s (expires in %d days)\n", cert.Subject, cert.DaysUntilExpiry)
			}
		} else {
			fmt.Printf("SSL analysis failed: %s\n", result.SSL.Error)
		}
	}

	// Step 4: HTTP Request
	fmt.Println("Executing HTTP request...")
	httpCtx, httpCancel := context.WithTimeout(ctx, a.cfg.Network.TimeoutTotal.Duration)
	httpResult, httpTimings := a.httpAuditor.Audit(httpCtx)
	httpCancel()

	result.HTTP = httpResult

	// Merge timings (HTTP timings may override DNS/TLS if they were measured during HTTP request)
	if httpTimings.DNSLookup.Duration > 0 {
		result.Timings.DNSLookup = httpTimings.DNSLookup
	}
	if httpTimings.TCPConnect.Duration > 0 {
		result.Timings.TCPConnect = httpTimings.TCPConnect
	}
	if httpTimings.TLSHandshake.Duration > 0 {
		result.Timings.TLSHandshake = httpTimings.TLSHandshake
	}
	result.Timings.FirstByte = httpTimings.FirstByte
	result.Timings.ContentRead = httpTimings.ContentRead
	result.Timings.Total = Duration{time.Since(overallStart)}

	if httpResult.Success {
		fmt.Printf("HTTP %s %d in %v\n", httpResult.Proto, httpResult.StatusCode, httpTimings.Total.Duration)
	} else {
		fmt.Printf("HTTP request failed: %s\n", httpResult.Error)
	}

	// Calculate summary
	result.CalculateSummary()

	return result
}

// GetInterfaceInfo returns information about the bound interface
func (a *Auditor) GetInterfaceInfo() string {
	if a.interfaceResolver == nil {
		return "default"
	}
	return fmt.Sprintf("%s (%s)", a.interfaceResolver.GetInterfaceName(), a.interfaceResolver.GetLocalIP())
}

// GetProxyInfo returns information about proxy configuration
func (a *Auditor) GetProxyInfo() proxy.ProxyInfo {
	if a.proxyConfig == nil {
		return proxy.ProxyInfo{Enabled: false}
	}
	return a.proxyConfig.GetInfo()
}
