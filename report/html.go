package report

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"strings"

	"http-audit/audit"
)

//go:embed templates/*.html
var templateFS embed.FS

// HTMLReporter generates HTML reports with charts
type HTMLReporter struct {
	template *template.Template
}

// TemplateData contains all data passed to the HTML template
type TemplateData struct {
	*audit.Result
	ChartJSURL string
}

// NewHTMLReporter creates a new HTML reporter
func NewHTMLReporter() (*HTMLReporter, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/report.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML template: %w", err)
	}

	return &HTMLReporter{
		template: tmpl,
	}, nil
}

// Generate creates an HTML report file from audit results
func (r *HTMLReporter) Generate(result *audit.Result, outputPath string, chartJSURL string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML report file: %w", err)
	}
	defer file.Close()

	data := TemplateData{
		Result:     result,
		ChartJSURL: chartJSURL,
	}

	if err := r.template.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return nil
}

// GenerateString returns the HTML report as a string
func (r *HTMLReporter) GenerateString(result *audit.Result, chartJSURL string) (string, error) {
	var buf strings.Builder

	data := TemplateData{
		Result:     result,
		ChartJSURL: chartJSURL,
	}

	if err := r.template.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute HTML template: %w", err)
	}
	return buf.String(), nil
}
