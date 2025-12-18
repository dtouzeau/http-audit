package audit

import (
	"encoding/json"
	"fmt"
	"time"
)

// Result contains the complete audit results
type Result struct {
	Timestamp time.Time      `json:"timestamp"`
	TargetURL string         `json:"target_url"`
	Success   bool           `json:"success"`
	Error     string         `json:"error,omitempty"`
	Keytab    *KeytabResult  `json:"keytab,omitempty"`
	DNS       *DNSResult     `json:"dns,omitempty"`
	Proxy     *ProxyResult   `json:"proxy,omitempty"`
	SSL       *SSLResult     `json:"ssl,omitempty"`
	HTTP      *HTTPResult    `json:"http,omitempty"`
	Timings   *TimingResult  `json:"timings"`
	Summary   *SummaryResult `json:"summary"`
}

// ProxyResult contains proxy communication details
type ProxyResult struct {
	Enabled        bool              `json:"enabled"`
	URL            string            `json:"url"`
	Host           string            `json:"host"`
	Port           string            `json:"port"`
	AuthType       string            `json:"auth_type,omitempty"`
	ConnectStatus  int               `json:"connect_status,omitempty"`
	ConnectHeaders map[string]string `json:"connect_headers,omitempty"`
	Error          string            `json:"error,omitempty"`
}

// KeytabResult contains keytab generation results
type KeytabResult struct {
	Success     bool      `json:"success"`
	Generated   bool      `json:"generated"`
	Path        string    `json:"path"`
	Principal   string    `json:"principal"`
	Error       string    `json:"error,omitempty"`
	Duration    Duration  `json:"duration"`
	GeneratedAt time.Time `json:"generated_at,omitempty"`
}

// DNSServerResult contains results from a single DNS server query
type DNSServerResult struct {
	Server      string   `json:"server"`
	Success     bool     `json:"success"`
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
	Duration    Duration `json:"duration"`
	Error       string   `json:"error,omitempty"`
}

// DNSResult contains DNS resolution results
type DNSResult struct {
	Success       bool              `json:"success"`
	Hostname      string            `json:"hostname"`
	ResolvedIPs   []string          `json:"resolved_ips"`
	ExpectedIPs   []string          `json:"expected_ips,omitempty"`
	IPsMatch      bool              `json:"ips_match"`
	ServerUsed    string            `json:"server_used,omitempty"`
	Duration      Duration          `json:"duration"`
	Error         string            `json:"error,omitempty"`
	ServerResults []DNSServerResult `json:"server_results,omitempty"`
	FastestServer string            `json:"fastest_server,omitempty"`
}

// SSLResult contains SSL/TLS analysis results
type SSLResult struct {
	Success           bool              `json:"success"`
	Connected         bool              `json:"connected"`
	Protocol          string            `json:"protocol"`
	CipherSuite       string            `json:"cipher_suite"`
	Certificates      []CertificateInfo `json:"certificates"`
	SupportedVersions []ProtocolSupport `json:"supported_versions,omitempty"`
	Duration          Duration          `json:"duration"`
	Error             string            `json:"error,omitempty"`
}

// CertificateInfo contains certificate details
type CertificateInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	IsExpired          bool      `json:"is_expired"`
	DaysUntilExpiry    int       `json:"days_until_expiry"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	IsCA               bool      `json:"is_ca"`
}

// ProtocolSupport indicates TLS version support
type ProtocolSupport struct {
	Version   string `json:"version"`
	Supported bool   `json:"supported"`
	Error     string `json:"error,omitempty"`
}

// HTTPResult contains HTTP request/response results
type HTTPResult struct {
	Success        bool              `json:"success"`
	StatusCode     int               `json:"status_code"`
	Status         string            `json:"status"`
	Proto          string            `json:"proto"`
	Headers        map[string]string `json:"headers"`
	ContentLength  int64             `json:"content_length"`
	ContentType    string            `json:"content_type"`
	UsedTLS        bool              `json:"used_tls"`
	TLSVersion     string            `json:"tls_version,omitempty"`
	TLSCipherSuite string            `json:"tls_cipher_suite,omitempty"`
	Body           string            `json:"body,omitempty"`
	BodyTruncated  bool              `json:"body_truncated"`
	Redirects      []RedirectInfo    `json:"redirects,omitempty"`
	RedirectCount  int               `json:"redirect_count"`
	FinalURL       string            `json:"final_url"`
	Error          string            `json:"error,omitempty"`
	RequestHeaders map[string]string `json:"request_headers"`
}

// RedirectInfo contains information about a redirect
type RedirectInfo struct {
	From       string            `json:"from"`
	To         string            `json:"to"`
	StatusCode int               `json:"status_code"`
	Status     string            `json:"status"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// TimingResult contains timing breakdown
type TimingResult struct {
	DNSLookup    Duration `json:"dns_lookup"`
	TCPConnect   Duration `json:"tcp_connect"`
	TLSHandshake Duration `json:"tls_handshake"`
	FirstByte    Duration `json:"first_byte"`
	ContentRead  Duration `json:"content_read"`
	Total        Duration `json:"total"`
}

// SummaryResult contains a high-level summary
type SummaryResult struct {
	TotalSteps    int      `json:"total_steps"`
	SuccessSteps  int      `json:"success_steps"`
	FailedSteps   int      `json:"failed_steps"`
	Warnings      []string `json:"warnings,omitempty"`
	OverallStatus string   `json:"overall_status"` // success, partial, failed
}

// Duration wraps time.Duration for JSON serialization
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.Duration.String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// Milliseconds returns the duration in milliseconds as float64
func (d Duration) Milliseconds() float64 {
	return float64(d.Duration.Nanoseconds()) / 1e6
}

// NewResult creates a new Result with initialized timestamp
func NewResult(targetURL string) *Result {
	return &Result{
		Timestamp: time.Now(),
		TargetURL: targetURL,
		Timings:   &TimingResult{},
		Summary:   &SummaryResult{},
	}
}

// SetError sets the overall error and marks success as false
func (r *Result) SetError(err error) {
	r.Success = false
	if err != nil {
		r.Error = err.Error()
	}
}

// CalculateSummary computes the summary from individual results
func (r *Result) CalculateSummary() {
	r.Summary.TotalSteps = 0
	r.Summary.SuccessSteps = 0
	r.Summary.FailedSteps = 0
	r.Summary.Warnings = []string{}

	// Count keytab step
	if r.Keytab != nil {
		r.Summary.TotalSteps++
		if r.Keytab.Success {
			r.Summary.SuccessSteps++
		} else {
			r.Summary.FailedSteps++
		}
	}

	// Count DNS step
	if r.DNS != nil {
		r.Summary.TotalSteps++
		if r.DNS.Success {
			r.Summary.SuccessSteps++
			if !r.DNS.IPsMatch && len(r.DNS.ExpectedIPs) > 0 {
				r.Summary.Warnings = append(r.Summary.Warnings, "DNS resolved IPs do not match expected IPs")
			}
		} else {
			r.Summary.FailedSteps++
		}
	}

	// Count SSL step
	if r.SSL != nil {
		r.Summary.TotalSteps++
		if r.SSL.Success {
			r.Summary.SuccessSteps++
			// Check for certificate warnings
			for _, cert := range r.SSL.Certificates {
				if cert.IsExpired {
					r.Summary.Warnings = append(r.Summary.Warnings, "Certificate is expired: "+cert.Subject)
				} else if cert.DaysUntilExpiry < 30 {
					r.Summary.Warnings = append(r.Summary.Warnings,
						fmt.Sprintf("Certificate expires in %d days: %s", cert.DaysUntilExpiry, cert.Subject))
				}
			}
		} else {
			r.Summary.FailedSteps++
		}
	}

	// Count HTTP step
	if r.HTTP != nil {
		r.Summary.TotalSteps++
		if r.HTTP.Success {
			r.Summary.SuccessSteps++
		} else {
			r.Summary.FailedSteps++
		}
	}

	// Determine overall status
	if r.Summary.FailedSteps == 0 && r.Summary.TotalSteps > 0 {
		r.Summary.OverallStatus = "success"
		r.Success = true
	} else if r.Summary.SuccessSteps > 0 {
		r.Summary.OverallStatus = "partial"
		r.Success = false
	} else {
		r.Summary.OverallStatus = "failed"
		r.Success = false
	}
}
