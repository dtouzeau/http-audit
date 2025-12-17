package network

import (
	"fmt"
	"net"
	"time"
)

// InterfaceResolver resolves network interface names to usable addresses
type InterfaceResolver struct {
	interfaceName string
	localAddr     net.Addr
}

// NewInterfaceResolver creates a resolver for the given interface name
func NewInterfaceResolver(interfaceName string) (*InterfaceResolver, error) {
	if interfaceName == "" {
		return &InterfaceResolver{}, nil
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %q: %w", interfaceName, err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("interface %q has no addresses", interfaceName)
	}

	// Find first IPv4 address
	var selectedAddr net.IP
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		// Prefer IPv4
		if ip4 := ip.To4(); ip4 != nil {
			selectedAddr = ip4
			break
		}
		// Fallback to IPv6 if no IPv4 found
		if selectedAddr == nil {
			selectedAddr = ip
		}
	}

	if selectedAddr == nil {
		return nil, fmt.Errorf("no usable IP address found on interface %q", interfaceName)
	}

	return &InterfaceResolver{
		interfaceName: interfaceName,
		localAddr:     &net.TCPAddr{IP: selectedAddr},
	}, nil
}

// GetDialer returns a net.Dialer configured to use the specified interface
func (r *InterfaceResolver) GetDialer(timeout time.Duration) *net.Dialer {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	if r.localAddr != nil {
		dialer.LocalAddr = r.localAddr
	}

	return dialer
}

// GetLocalIP returns the local IP address being used
func (r *InterfaceResolver) GetLocalIP() string {
	if r.localAddr == nil {
		return ""
	}
	if tcpAddr, ok := r.localAddr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}
	return r.localAddr.String()
}

// GetInterfaceName returns the configured interface name
func (r *InterfaceResolver) GetInterfaceName() string {
	return r.interfaceName
}

// ListInterfaces returns a list of available network interfaces
func ListInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		info := InterfaceInfo{
			Name:  iface.Name,
			Flags: iface.Flags.String(),
			MTU:   iface.MTU,
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				info.Addresses = append(info.Addresses, addr.String())
			}
		}

		result = append(result, info)
	}

	return result, nil
}

// InterfaceInfo contains information about a network interface
type InterfaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Flags     string   `json:"flags"`
	MTU       int      `json:"mtu"`
}
