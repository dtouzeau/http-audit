package audit

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"http-audit/config"
)

// DNSAuditor performs DNS resolution checks
type DNSAuditor struct {
	cfg      *config.Config
	resolver *net.Resolver
}

// NewDNSAuditor creates a new DNS auditor
func NewDNSAuditor(cfg *config.Config) *DNSAuditor {
	auditor := &DNSAuditor{
		cfg: cfg,
	}

	// Configure custom DNS servers if specified
	if len(cfg.DNS.Servers) > 0 {
		auditor.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: cfg.Network.TimeoutConnect.Duration,
				}
				// Use the first configured DNS server
				server := cfg.DNS.Servers[0]
				if _, _, err := net.SplitHostPort(server); err != nil {
					server = net.JoinHostPort(server, "53")
				}
				return d.DialContext(ctx, "udp", server)
			},
		}
	} else {
		auditor.resolver = net.DefaultResolver
	}

	return auditor
}

// Audit performs DNS resolution and returns results
func (a *DNSAuditor) Audit(ctx context.Context) *DNSResult {
	result := &DNSResult{
		Hostname:    a.cfg.GetTargetHost(),
		ExpectedIPs: a.cfg.DNS.ExpectIPs,
		IPsMatch:    true,
	}

	if !a.cfg.DNS.Enabled {
		result.Success = true
		return result
	}

	start := time.Now()

	// Resolve hostname
	ips, err := a.resolver.LookupIP(ctx, "ip", result.Hostname)
	result.Duration = Duration{time.Since(start)}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}

	// Convert IPs to strings
	for _, ip := range ips {
		result.ResolvedIPs = append(result.ResolvedIPs, ip.String())
	}

	// Record which server was used
	if len(a.cfg.DNS.Servers) > 0 {
		result.ServerUsed = a.cfg.DNS.Servers[0]
	} else {
		result.ServerUsed = "system default"
	}

	// Check if resolved IPs match expected IPs
	if len(a.cfg.DNS.ExpectIPs) > 0 {
		result.IPsMatch = a.compareIPs(result.ResolvedIPs, a.cfg.DNS.ExpectIPs)
	}

	result.Success = true
	return result
}

// compareIPs checks if all expected IPs are in the resolved IPs
func (a *DNSAuditor) compareIPs(resolved, expected []string) bool {
	resolvedSet := make(map[string]bool)
	for _, ip := range resolved {
		resolvedSet[ip] = true
	}

	for _, ip := range expected {
		if !resolvedSet[ip] {
			return false
		}
	}
	return true
}

// ResolveWithAllServers resolves using all configured DNS servers and returns results
func (a *DNSAuditor) ResolveWithAllServers(ctx context.Context) map[string]*DNSResult {
	results := make(map[string]*DNSResult)
	hostname := a.cfg.GetTargetHost()

	servers := a.cfg.DNS.Servers
	if len(servers) == 0 {
		servers = []string{"system"}
	}

	for _, server := range servers {
		var resolver *net.Resolver
		if server == "system" {
			resolver = net.DefaultResolver
		} else {
			serverAddr := server
			if _, _, err := net.SplitHostPort(serverAddr); err != nil {
				serverAddr = net.JoinHostPort(serverAddr, "53")
			}
			resolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: a.cfg.Network.TimeoutConnect.Duration,
					}
					return d.DialContext(ctx, "udp", serverAddr)
				},
			}
		}

		result := &DNSResult{
			Hostname:   hostname,
			ServerUsed: server,
		}

		start := time.Now()
		ips, err := resolver.LookupIP(ctx, "ip", hostname)
		result.Duration = Duration{time.Since(start)}

		if err != nil {
			result.Success = false
			result.Error = err.Error()
		} else {
			result.Success = true
			for _, ip := range ips {
				result.ResolvedIPs = append(result.ResolvedIPs, ip.String())
			}
			sort.Strings(result.ResolvedIPs)
		}

		results[server] = result
	}

	return results
}

// GetResolvedIP returns the first resolved IP for the target host
func (a *DNSAuditor) GetResolvedIP(ctx context.Context) (string, error) {
	hostname := a.cfg.GetTargetHost()
	ips, err := a.resolver.LookupIP(ctx, "ip4", hostname)
	if err != nil {
		// Fallback to IPv6
		ips, err = a.resolver.LookupIP(ctx, "ip6", hostname)
		if err != nil {
			return "", fmt.Errorf("failed to resolve %s: %w", hostname, err)
		}
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for %s", hostname)
	}
	return ips[0].String(), nil
}
