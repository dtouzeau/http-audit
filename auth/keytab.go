package auth

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"http-audit/config"
)

// KeytabResult contains keytab generation results
type KeytabResult struct {
	Success     bool
	Generated   bool
	Path        string
	Principal   string
	Error       string
	Duration    time.Duration
	GeneratedAt time.Time
}

// KeytabGenerator generates Kerberos keytab files using ktutil
type KeytabGenerator struct {
	cfg *config.KerberosConfig
}

// NewKeytabGenerator creates a new keytab generator
func NewKeytabGenerator(cfg *config.KerberosConfig) *KeytabGenerator {
	return &KeytabGenerator{cfg: cfg}
}

// Generate creates a keytab file from credentials
func (g *KeytabGenerator) Generate() *KeytabResult {
	result := &KeytabResult{
		Path:      g.cfg.KeytabPath,
		Principal: g.cfg.Username,
	}

	start := time.Now()

	// Check if keytab already exists and generation is not forced
	if !g.cfg.GenerateKeytab {
		if _, err := os.Stat(g.cfg.KeytabPath); err == nil {
			result.Success = true
			result.Generated = false
			result.Duration = time.Since(start)
			return result
		}
	}

	// Ensure the keytab directory exists
	keytabDir := filepath.Dir(g.cfg.KeytabPath)
	if err := os.MkdirAll(keytabDir, 0700); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("failed to create keytab directory: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Remove existing keytab if it exists
	if _, err := os.Stat(g.cfg.KeytabPath); err == nil {
		if err := os.Remove(g.cfg.KeytabPath); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("failed to remove existing keytab: %v", err)
			result.Duration = time.Since(start)
			return result
		}
	}

	// Generate keytab using ktutil
	err := g.runKtutil()
	result.Duration = time.Since(start)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}

	// Verify keytab was created
	if _, err := os.Stat(g.cfg.KeytabPath); os.IsNotExist(err) {
		result.Success = false
		result.Error = "keytab file was not created"
		return result
	}

	result.Success = true
	result.Generated = true
	result.GeneratedAt = time.Now()
	return result
}

// runKtutil executes ktutil to generate the keytab
func (g *KeytabGenerator) runKtutil() error {
	// Build the principal name
	principal := g.cfg.Username
	if !strings.Contains(principal, "@") && g.cfg.Realm != "" {
		principal = principal + "@" + g.cfg.Realm
	}

	// Create ktutil commands
	// ktutil expects interactive input, so we'll pipe commands to it
	commands := fmt.Sprintf(`add_entry -password -p %s -k 1 -e aes256-cts-hmac-sha1-96
%s
add_entry -password -p %s -k 1 -e aes128-cts-hmac-sha1-96
%s
write_kt %s
quit
`, principal, g.cfg.Password, principal, g.cfg.Password, g.cfg.KeytabPath)

	cmd := exec.Command("ktutil")
	cmd.Stdin = strings.NewReader(commands)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ktutil failed: %v, output: %s", err, string(output))
	}

	return nil
}

// ValidateKeytab checks if a keytab file is valid
func (g *KeytabGenerator) ValidateKeytab() error {
	if _, err := os.Stat(g.cfg.KeytabPath); os.IsNotExist(err) {
		return fmt.Errorf("keytab file does not exist: %s", g.cfg.KeytabPath)
	}

	// Use klist to validate the keytab
	cmd := exec.Command("klist", "-k", g.cfg.KeytabPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keytab validation failed: %v, output: %s", err, string(output))
	}

	return nil
}

// ListKeytabEntries returns the entries in a keytab file
func ListKeytabEntries(keytabPath string) ([]string, error) {
	cmd := exec.Command("klist", "-k", keytabPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list keytab entries: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	var entries []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Keytab") && !strings.HasPrefix(line, "KVNO") && !strings.HasPrefix(line, "----") {
			entries = append(entries, line)
		}
	}

	return entries, nil
}

// KinitWithKeytab performs kinit using a keytab file
func KinitWithKeytab(principal, keytabPath string) error {
	cmd := exec.Command("kinit", "-kt", keytabPath, principal)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kinit failed: %v, output: %s", err, string(output))
	}
	return nil
}

// GetCurrentTickets returns current Kerberos tickets
func GetCurrentTickets() (string, error) {
	cmd := exec.Command("klist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("klist failed: %v", err)
	}
	return string(output), nil
}
