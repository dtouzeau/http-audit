package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"http-audit/config"
	"http-audit/network"
)

// SSLAuditor performs SSL/TLS analysis
type SSLAuditor struct {
	cfg               *config.Config
	interfaceResolver *network.InterfaceResolver
}

// NewSSLAuditor creates a new SSL auditor
func NewSSLAuditor(cfg *config.Config, ifaceResolver *network.InterfaceResolver) *SSLAuditor {
	return &SSLAuditor{
		cfg:               cfg,
		interfaceResolver: ifaceResolver,
	}
}

// Audit performs SSL/TLS analysis and returns results
func (a *SSLAuditor) Audit(ctx context.Context) *SSLResult {
	result := &SSLResult{
		Certificates:      []CertificateInfo{},
		SupportedVersions: []ProtocolSupport{},
	}

	if !a.cfg.IsHTTPS() {
		result.Success = true
		result.Error = "target is not HTTPS"
		return result
	}

	host := a.cfg.GetTargetHost()
	port := a.cfg.GetTargetPort()
	addr := net.JoinHostPort(host, port)

	start := time.Now()

	// Get dialer
	dialer := a.getDialer()

	// Connect with TLS
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !a.cfg.SSL.Verify,
		MinVersion:         a.getMinTLSVersion(),
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("TLS connection failed: %v", err)
		result.Duration = Duration{time.Since(start)}
		return result
	}
	defer conn.Close()

	result.Duration = Duration{time.Since(start)}
	result.Connected = true

	// Get connection state
	state := conn.ConnectionState()
	result.Protocol = tlsVersionToString(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Extract certificate information
	for _, cert := range state.PeerCertificates {
		certInfo := a.extractCertInfo(cert)
		result.Certificates = append(result.Certificates, certInfo)
	}

	// Check supported TLS versions if requested
	if a.cfg.SSL.CheckProtocols {
		result.SupportedVersions = a.checkProtocolSupport(ctx, addr, host)
	}

	result.Success = true
	return result
}

// getDialer returns the appropriate dialer
func (a *SSLAuditor) getDialer() *net.Dialer {
	if a.interfaceResolver != nil {
		return a.interfaceResolver.GetDialer(a.cfg.Network.TimeoutConnect.Duration)
	}
	return &net.Dialer{
		Timeout: a.cfg.Network.TimeoutConnect.Duration,
	}
}

// getMinTLSVersion converts config string to tls version constant
func (a *SSLAuditor) getMinTLSVersion() uint16 {
	switch a.cfg.SSL.MinVersion {
	case "TLS1.0":
		return tls.VersionTLS10
	case "TLS1.1":
		return tls.VersionTLS11
	case "TLS1.2":
		return tls.VersionTLS12
	case "TLS1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// extractCertInfo extracts relevant information from a certificate
func (a *SSLAuditor) extractCertInfo(cert *x509.Certificate) CertificateInfo {
	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	info := CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsExpired:          now.After(cert.NotAfter),
		DaysUntilExpiry:    daysUntilExpiry,
		DNSNames:           cert.DNSNames,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		IsCA:               cert.IsCA,
	}

	// Convert IP addresses to strings
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	return info
}

// checkProtocolSupport tests which TLS versions are supported
func (a *SSLAuditor) checkProtocolSupport(ctx context.Context, addr, serverName string) []ProtocolSupport {
	versions := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.0", tls.VersionTLS10},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13},
	}

	var results []ProtocolSupport

	for _, v := range versions {
		support := ProtocolSupport{
			Version: v.name,
		}

		tlsConfig := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         v.version,
			MaxVersion:         v.version,
		}

		dialer := a.getDialer()
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			support.Supported = false
			support.Error = err.Error()
		} else {
			support.Supported = true
			conn.Close()
		}

		results = append(results, support)
	}

	return results
}

// tlsVersionToString converts TLS version constant to string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionSSL30:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// GetCipherSuites returns information about available cipher suites
func GetCipherSuites() []CipherSuiteInfo {
	var suites []CipherSuiteInfo

	for _, suite := range tls.CipherSuites() {
		suites = append(suites, CipherSuiteInfo{
			ID:                suite.ID,
			Name:              suite.Name,
			SupportedVersions: tlsVersionsToStrings(suite.SupportedVersions),
			Insecure:          false,
		})
	}

	for _, suite := range tls.InsecureCipherSuites() {
		suites = append(suites, CipherSuiteInfo{
			ID:                suite.ID,
			Name:              suite.Name,
			SupportedVersions: tlsVersionsToStrings(suite.SupportedVersions),
			Insecure:          true,
		})
	}

	return suites
}

// CipherSuiteInfo contains cipher suite information
type CipherSuiteInfo struct {
	ID                uint16   `json:"id"`
	Name              string   `json:"name"`
	SupportedVersions []string `json:"supported_versions"`
	Insecure          bool     `json:"insecure"`
}

func tlsVersionsToStrings(versions []uint16) []string {
	var result []string
	for _, v := range versions {
		result = append(result, tlsVersionToString(v))
	}
	return result
}
