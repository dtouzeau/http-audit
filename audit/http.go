package audit

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"http-audit/auth"
	"http-audit/config"
	"http-audit/network"
	"http-audit/proxy"
)

const maxBodySize = 1024 * 1024 // 1MB max body capture

// HTTPAuditor performs HTTP request auditing
type HTTPAuditor struct {
	cfg               *config.Config
	interfaceResolver *network.InterfaceResolver
	proxyConfig       *proxy.ProxyConfig
	basicAuth         *auth.BasicAuthenticator
	kerberosAuth      *auth.KerberosAuthenticator
}

// NewHTTPAuditor creates a new HTTP auditor
func NewHTTPAuditor(
	cfg *config.Config,
	ifaceResolver *network.InterfaceResolver,
	proxyConfig *proxy.ProxyConfig,
) *HTTPAuditor {
	return &HTTPAuditor{
		cfg:               cfg,
		interfaceResolver: ifaceResolver,
		proxyConfig:       proxyConfig,
	}
}

// SetBasicAuth sets the basic authenticator
func (a *HTTPAuditor) SetBasicAuth(auth *auth.BasicAuthenticator) {
	a.basicAuth = auth
}

// SetKerberosAuth sets the Kerberos authenticator
func (a *HTTPAuditor) SetKerberosAuth(auth *auth.KerberosAuthenticator) {
	a.kerberosAuth = auth
}

// redirectCapture wraps a RoundTripper to capture redirect responses
type redirectCapture struct {
	transport http.RoundTripper
	redirects *[]RedirectInfo
}

func (rc *redirectCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rc.transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Capture redirect responses (3xx status codes)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		headers := make(map[string]string)
		for key, values := range resp.Header {
			headers[key] = strings.Join(values, ", ")
		}
		*rc.redirects = append(*rc.redirects, RedirectInfo{
			From:       req.URL.String(),
			To:         location,
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Headers:    headers,
		})
	}

	return resp, err
}

// Audit performs the HTTP request and returns results
func (a *HTTPAuditor) Audit(ctx context.Context) (*HTTPResult, *TimingResult) {
	result := &HTTPResult{
		Headers:        make(map[string]string),
		RequestHeaders: make(map[string]string),
		Redirects:      []RedirectInfo{},
	}

	timings := &TimingResult{}

	// Create transport
	transport := a.createTransport()

	// Create redirect capture wrapper
	var redirects []RedirectInfo
	captureTransport := &redirectCapture{
		transport: transport,
		redirects: &redirects,
	}

	// Create HTTP client
	client := &http.Client{
		Transport: captureTransport,
		Timeout:   a.cfg.Network.TimeoutTotal.Duration,
	}

	// Handle redirects
	if a.cfg.HTTP.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= a.cfg.HTTP.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", a.cfg.HTTP.MaxRedirects)
			}
			// Re-apply auth headers on redirect
			a.applyAuthToRequest(req)
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Create request
	var bodyReader io.Reader
	if a.cfg.Target.Body != "" {
		bodyReader = strings.NewReader(a.cfg.Target.Body)
	}

	req, err := http.NewRequestWithContext(ctx, a.cfg.Target.Method, a.cfg.Target.URL, bodyReader)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result, timings
	}

	// Set headers
	req.Header.Set("User-Agent", a.cfg.HTTP.UserAgent)
	req.Header.Set("Accept-Language", a.cfg.HTTP.AcceptLanguage)
	req.Header.Set("Accept-Encoding", a.cfg.HTTP.AcceptEncoding)
	req.Header.Set("Connection", a.cfg.HTTP.Connection)
	if a.cfg.HTTP.Referer != "" {
		req.Header.Set("Referer", a.cfg.HTTP.Referer)
	}
	if a.cfg.HTTP.XForwardedFor != "" {
		req.Header.Set("X-Forwarded-For", a.cfg.HTTP.XForwardedFor)
	}
	for key, value := range a.cfg.Target.Headers {
		req.Header.Set(key, value)
	}

	// Apply authentication
	if err := a.applyAuthToRequest(req); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("failed to apply authentication: %v", err)
		return result, timings
	}

	// Apply proxy auth
	if a.proxyConfig != nil {
		a.proxyConfig.ApplyToRequest(req)
	}

	// Record request headers
	for key, values := range req.Header {
		result.RequestHeaders[key] = strings.Join(values, ", ")
	}

	// Setup request tracing
	var dnsStart, dnsEnd time.Time
	var connectStart, connectEnd time.Time
	var tlsStart, tlsEnd time.Time
	var firstByteTime time.Time
	requestStart := time.Now()

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dnsEnd = time.Now()
		},
		ConnectStart: func(network, addr string) {
			connectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connectEnd = time.Now()
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsEnd = time.Now()
		},
		GotFirstResponseByte: func() {
			firstByteTime = time.Now()
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("request failed: %v", err)
		a.calculateTimings(timings, requestStart, dnsStart, dnsEnd, connectStart, connectEnd, tlsStart, tlsEnd, firstByteTime, time.Now())
		return result, timings
	}
	defer resp.Body.Close()

	// Read response body
	bodyStart := time.Now()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	bodyEnd := time.Now()

	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("failed to read response body: %v", err)
		return result, timings
	}

	// Calculate timings
	a.calculateTimings(timings, requestStart, dnsStart, dnsEnd, connectStart, connectEnd, tlsStart, tlsEnd, firstByteTime, bodyEnd)
	timings.ContentRead = Duration{bodyEnd.Sub(bodyStart)}

	// Populate result
	result.Success = true
	result.StatusCode = resp.StatusCode
	result.Status = resp.Status
	result.Proto = resp.Proto
	result.ContentLength = resp.ContentLength
	result.FinalURL = resp.Request.URL.String()
	result.Redirects = redirects
	result.RedirectCount = len(redirects)

	// Capture TLS state if connection used HTTPS
	if resp.TLS != nil {
		result.UsedTLS = true
		result.TLSVersion = tlsVersionName(resp.TLS.Version)
		result.TLSCipherSuite = tls.CipherSuiteName(resp.TLS.CipherSuite)
	}

	// Response headers
	for key, values := range resp.Header {
		result.Headers[key] = strings.Join(values, ", ")
	}

	// Content type
	result.ContentType = resp.Header.Get("Content-Type")

	// Body (truncated if too large)
	result.Body = string(body)
	if resp.ContentLength > maxBodySize || len(body) == maxBodySize {
		result.BodyTruncated = true
	}

	return result, timings
}

// createTransport creates an HTTP transport with all configurations
func (a *HTTPAuditor) createTransport() *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Configure TLS
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: !a.cfg.SSL.Verify,
		MinVersion:         a.getMinTLSVersion(),
	}

	// Configure dialer
	dialer := &net.Dialer{
		Timeout:   a.cfg.Network.TimeoutConnect.Duration,
		KeepAlive: 30 * time.Second,
	}

	// Apply interface binding
	if a.interfaceResolver != nil {
		boundDialer := a.interfaceResolver.GetDialer(a.cfg.Network.TimeoutConnect.Duration)
		dialer.LocalAddr = boundDialer.LocalAddr
	}

	transport.DialContext = dialer.DialContext

	// Apply proxy
	if a.proxyConfig != nil && a.proxyConfig.IsEnabled() {
		a.proxyConfig.ApplyToTransport(transport)
	}

	return transport
}

// applyAuthToRequest applies the appropriate authentication to the request
func (a *HTTPAuditor) applyAuthToRequest(req *http.Request) error {
	switch a.cfg.Auth.Type {
	case "basic":
		if a.basicAuth != nil {
			a.basicAuth.ApplyToRequest(req)
		}
	case "kerberos":
		if a.kerberosAuth != nil {
			if err := a.kerberosAuth.ApplyToRequest(req); err != nil {
				return err
			}
		}
	}
	return nil
}

// getMinTLSVersion converts config string to TLS version constant
func (a *HTTPAuditor) getMinTLSVersion() uint16 {
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

// calculateTimings computes timing breakdowns
func (a *HTTPAuditor) calculateTimings(
	timings *TimingResult,
	requestStart, dnsStart, dnsEnd, connectStart, connectEnd, tlsStart, tlsEnd, firstByteTime, endTime time.Time,
) {
	if !dnsStart.IsZero() && !dnsEnd.IsZero() {
		timings.DNSLookup = Duration{dnsEnd.Sub(dnsStart)}
	}
	if !connectStart.IsZero() && !connectEnd.IsZero() {
		timings.TCPConnect = Duration{connectEnd.Sub(connectStart)}
	}
	if !tlsStart.IsZero() && !tlsEnd.IsZero() {
		timings.TLSHandshake = Duration{tlsEnd.Sub(tlsStart)}
	}
	if !firstByteTime.IsZero() {
		timings.FirstByte = Duration{firstByteTime.Sub(requestStart)}
	}
	timings.Total = Duration{endTime.Sub(requestStart)}
}

// tlsVersionName returns a human-readable TLS version name
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
