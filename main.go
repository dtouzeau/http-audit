package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"http-audit/audit"
	"http-audit/config"
	"http-audit/report"
)

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "config.json", "Path to JSON configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("http-audit version %s\n", version)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("===========================================")
	fmt.Println("           HTTP Audit Tool v" + version)
	fmt.Println("===========================================")
	fmt.Printf("Target URL: %s\n", cfg.Target.URL)
	fmt.Printf("Method: %s\n", cfg.Target.Method)
	if cfg.Network.Interface != "" {
		fmt.Printf("Network Interface: %s\n", cfg.Network.Interface)
	}
	if cfg.Proxy.Enabled {
		fmt.Printf("Proxy: %s\n", cfg.Proxy.URL)
	}
	if cfg.Auth.Type != "" && cfg.Auth.Type != "none" {
		fmt.Printf("Authentication: %s\n", cfg.Auth.Type)
	}
	fmt.Println("-------------------------------------------")

	// Create audit context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupted, cancelling audit...")
		cancel()
	}()

	// Create auditor
	auditor, err := audit.NewAuditor(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating auditor: %v\n", err)
		os.Exit(1)
	}

	// Run audit
	result := auditor.Run(ctx)

	fmt.Println("-------------------------------------------")

	// Generate reports
	if err := generateReports(cfg, result); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating reports: %v\n", err)
		os.Exit(1)
	}

	// Print summary
	printSummary(result)

	// Exit with appropriate code
	if result.Success {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func generateReports(cfg *config.Config, result *audit.Result) error {
	// Generate JSON report
	if cfg.Output.JSONPath != "" {
		jsonReporter := report.NewJSONReporter()
		if err := jsonReporter.Generate(result, cfg.Output.JSONPath); err != nil {
			return fmt.Errorf("JSON report: %w", err)
		}
		fmt.Printf("JSON report saved to: %s\n", cfg.Output.JSONPath)
	}

	// Generate HTML report
	if cfg.Output.HTMLPath != "" {
		htmlReporter, err := report.NewHTMLReporter()
		if err != nil {
			return fmt.Errorf("HTML reporter init: %w", err)
		}
		if err := htmlReporter.Generate(result, cfg.Output.HTMLPath, cfg.Output.ChartJSURL); err != nil {
			return fmt.Errorf("HTML report: %w", err)
		}
		fmt.Printf("HTML report saved to: %s\n", cfg.Output.HTMLPath)
	}

	return nil
}

func printSummary(result *audit.Result) {
	fmt.Println("===========================================")
	fmt.Println("                 SUMMARY")
	fmt.Println("===========================================")

	// Overall status
	statusIcon := "✓"
	statusText := "SUCCESS"
	if result.Summary.OverallStatus == "partial" {
		statusIcon = "⚠"
		statusText = "PARTIAL"
	} else if result.Summary.OverallStatus == "failed" {
		statusIcon = "✗"
		statusText = "FAILED"
	}
	fmt.Printf("Status: %s %s\n", statusIcon, statusText)
	fmt.Printf("Steps: %d/%d successful\n", result.Summary.SuccessSteps, result.Summary.TotalSteps)
	fmt.Printf("Total Time: %v\n", result.Timings.Total.Duration)

	// Timing breakdown
	fmt.Println("\nTiming Breakdown:")
	if result.Timings.DNSLookup.Duration > 0 {
		fmt.Printf("  DNS Lookup:    %v\n", result.Timings.DNSLookup.Duration)
	}
	if result.Timings.TCPConnect.Duration > 0 {
		fmt.Printf("  TCP Connect:   %v\n", result.Timings.TCPConnect.Duration)
	}
	if result.Timings.TLSHandshake.Duration > 0 {
		fmt.Printf("  TLS Handshake: %v\n", result.Timings.TLSHandshake.Duration)
	}
	if result.Timings.FirstByte.Duration > 0 {
		fmt.Printf("  First Byte:    %v\n", result.Timings.FirstByte.Duration)
	}
	if result.Timings.ContentRead.Duration > 0 {
		fmt.Printf("  Content Read:  %v\n", result.Timings.ContentRead.Duration)
	}

	// HTTP result
	if result.HTTP != nil && result.HTTP.Success {
		fmt.Printf("\nHTTP Response: %d %s\n", result.HTTP.StatusCode, result.HTTP.Status)
	}

	// Warnings
	if len(result.Summary.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range result.Summary.Warnings {
			fmt.Printf("  ⚠ %s\n", w)
		}
	}

	// Error
	if result.Error != "" {
		fmt.Printf("\nError: %s\n", result.Error)
	}

	fmt.Println("===========================================")
}
