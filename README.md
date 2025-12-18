# http-audit

An HTTP auditing tool written in Go that investigates all steps required to access a URL. 

It provides detailed analysis of DNS resolution, SSL/TLS certificates, HTTP responses, and generates visual HTML reports with Chart.js.

## Features

- **DNS Resolution Analysis**: Custom DNS servers, IP validation, resolution timing
- **SSL/TLS Inspection**: Certificate chain analysis, protocol version detection, cipher suite identification
- **HTTP Request Auditing**: Detailed timing breakdown, redirect tracking, header inspection
- **Authentication Support**: HTTP Basic and Kerberos/SPNEGO with automatic keytab generation
- **Proxy Support**: HTTP proxy with authentication
- **Network Interface Binding**: Specify outgoing network interface
- **Detailed Reports**: HTML reports with Chart.js visualizations and JSON exports

## Quick Start

1. Create a configuration file (see `examples/config.json`):

```json
{
  "target": {
    "url": "https://www.articatech.com",
    "method": "GET"
  },
  "dns": {
    "enabled": true
  },
  "ssl": {
    "verify": true,
    "check_protocols": true
  },
  "output": {
    "html_path": "./report.html",
    "json_path": "./report.json"
  }
}
```

2. Run the audit:

```bash
./http-audit -config config.json
```

3. View the generated HTML report in your browser.

## Usage
### -config
```bash
# Run with configuration file
./http-audit -config config.json

# Show version
./http-audit -version
```
### -url

Overrides the `target.url` value from the configuration file. 
Useful for running the same configuration against different endpoints without modifying the config file.

```bash
# Override URL
./http-audit -config config.json -url https://wiki.articatech.com
```
### -interface

Overrides the `network.interface` value from the configuration file. Binds outgoing connections to a specific network interface.

```bash
# Bind to specific interface
./http-audit -config config.json -interface eth0
```

### Combined Overrides

```bash
# Override both URL and interface
./http-audit -config config.json -url http://articatech.net -interface eth1
```

### Example Configurations

- `examples/config.json` - Basic HTTPS audit
- `examples/config-with-proxy.json` - Audit through HTTP proxy
- `examples/config-kerberos.json` - Audit with Kerberos authentication

### Key Configuration Options

| Section | Option | Description |
|---------|--------|-------------|
| `target.url` | string | Target URL to audit (required) |
| `target.method` | string | HTTP method (default: GET) |
| `network.interface` | string | Bind to specific network interface |
| `network.timeout_total` | duration | Total request timeout (default: 60s) |
| `dns.enabled` | bool | Enable DNS resolution check |
| `dns.servers` | array | Custom DNS servers |
| `proxy.enabled` | bool | Enable HTTP proxy |
| `proxy.url` | string | Proxy URL |
| `auth.type` | string | Authentication type: none, basic, kerberos |
| `ssl.verify` | bool | Verify SSL certificates |
| `ssl.check_protocols` | bool | Check supported TLS versions |
| `output.html_path` | string | HTML report output path |
| `output.json_path` | string | JSON report output path |
| `output.chartjs_url` | string | Chart.js library URL for HTML reports |

## Output

### Console Output

```
===========================================
           HTTP Audit Tool v1.1.1
===========================================
Target URL: https://example.com
Method: GET
-------------------------------------------
Performing DNS resolution...
DNS resolved example.com to [93.184.216.34] in 15.234ms
Analyzing SSL/TLS...
SSL connected with TLS 1.3 using TLS_AES_256_GCM_SHA384
Certificate: CN=example.com (expires in 365 days)
Executing HTTP request...
HTTP HTTP/2.0 200 in 245.123ms
-------------------------------------------
JSON report saved to: ./report.json
HTML report saved to: ./report.html
===========================================
                 SUMMARY
===========================================
Status: SUCCESS
Steps: 3/3 successful
Total Time: 312.456ms
```

### HTML Report

The HTML report includes:
- Summary dashboard with success/failure status
- Timing waterfall chart (DNS, TCP, TLS, First Byte)
- DNS resolution details
- SSL/TLS certificate chain with expiry warnings
- TLS version support matrix
- HTTP response headers and redirect chain
- Request headers sent

### JSON Report

Machine-readable JSON output containing all audit data for integration with other tools.

## Authentication

### Basic Authentication

```json
{
  "auth": {
    "type": "basic",
    "basic": {
      "username": "user",
      "password": "password"
    }
  }
}
```

### Kerberos Authentication

```json
{
  "auth": {
    "type": "kerberos",
    "kerberos": {
      "username": "user@REALM.COM",
      "password": "password",
      "kdc_server": "kdc.realm.com",
      "realm": "REALM.COM",
      "keytab_path": "/tmp/user.keytab",
      "generate_keytab": true
    }
  }
}
```

When `generate_keytab` is `true`, the tool will automatically generate a keytab file using `ktutil` before performing the HTTP request.

## Proxy Configuration

```json
{
  "proxy": {
    "enabled": true,
    "url": "http://proxy.example.com:8080",
    "auth": {
      "type": "basic",
      "username": "proxyuser",
      "password": "proxypass"
    }
  }
}
```

## Chart.js Configuration

By default, Chart.js is loaded from the jsdelivr CDN. For offline use or to use a local copy:

```json
{
  "output": {
    "chartjs_url": "file:///path/to/chart.js"
  }
}
```

Or use a different CDN:

```json
{
  "output": {
    "chartjs_url": "https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"
  }
}
```

## Exit Codes

- `0` - All audit steps successful
- `1` - One or more audit steps failed

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
