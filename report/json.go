package report

import (
	"encoding/json"
	"fmt"
	"os"

	"http-audit/audit"
)

// JSONReporter generates JSON reports
type JSONReporter struct{}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

// Generate creates a JSON report file from audit results
func (r *JSONReporter) Generate(result *audit.Result, outputPath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result to JSON: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report to %s: %w", outputPath, err)
	}

	return nil
}

// GenerateString returns the JSON report as a string
func (r *JSONReporter) GenerateString(result *audit.Result) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result to JSON: %w", err)
	}
	return string(data), nil
}
