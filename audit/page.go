package audit

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"http-audit/config"
)

// PageAnalyzer extracts and tests resources from HTML content
type PageAnalyzer struct {
	cfg     *config.Config
	baseURL *url.URL
	client  *http.Client
}

// NewPageAnalyzer creates a new page analyzer
func NewPageAnalyzer(cfg *config.Config, baseURL string) (*PageAnalyzer, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	// Create HTTP client for resource fetching
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.SSL.Verify,
		},
		DialContext: (&net.Dialer{
			Timeout:   cfg.PageAnalysis.Timeout.Duration,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.PageAnalysis.Timeout.Duration,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &PageAnalyzer{
		cfg:     cfg,
		baseURL: parsedURL,
		client:  client,
	}, nil
}

// Analyze parses HTML content and fetches all resources
func (p *PageAnalyzer) Analyze(ctx context.Context, htmlContent string) *PageAnalysis {
	result := &PageAnalysis{
		Enabled:   true,
		Resources: []PageResource{},
	}

	// Extract all resource URLs from HTML
	resources := p.extractResources(htmlContent)

	// Limit the number of requests (0 means unlimited)
	if p.cfg.PageAnalysis.MaxRequests > 0 && len(resources) > p.cfg.PageAnalysis.MaxRequests {
		resources = resources[:p.cfg.PageAnalysis.MaxRequests]
	}

	result.TotalResources = len(resources)

	if len(resources) == 0 {
		return result
	}

	// Fetch resources in parallel
	var wg sync.WaitGroup
	resultsChan := make(chan PageResource, len(resources))
	semaphore := make(chan struct{}, 10) // Limit concurrent requests

	startTime := time.Now()

	for _, res := range resources {
		wg.Add(1)
		go func(resource resourceInfo) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			pageRes := p.fetchResource(ctx, resource)
			resultsChan <- pageRes
		}(res)
	}

	// Wait for all fetches to complete
	wg.Wait()
	close(resultsChan)

	result.TotalDuration = Duration{time.Since(startTime)}

	// Collect results
	var slowestDuration time.Duration
	for pageRes := range resultsChan {
		result.Resources = append(result.Resources, pageRes)
		if pageRes.Success {
			result.SuccessCount++
		} else {
			result.FailedCount++
		}
		if pageRes.Duration.Duration > slowestDuration {
			slowestDuration = pageRes.Duration.Duration
			result.SlowestURL = pageRes.URL
			result.SlowestTime = pageRes.Duration
		}
	}

	// Sort by duration (slowest first)
	sort.Slice(result.Resources, func(i, j int) bool {
		return result.Resources[i].Duration.Duration > result.Resources[j].Duration.Duration
	})

	return result
}

// resourceInfo holds extracted resource information
type resourceInfo struct {
	url     string
	resType string
}

// extractResources parses HTML and extracts resource URLs
func (p *PageAnalyzer) extractResources(html string) []resourceInfo {
	var resources []resourceInfo
	seen := make(map[string]bool)

	// Check which types to extract
	typeSet := make(map[string]bool)
	for _, t := range p.cfg.PageAnalysis.Types {
		typeSet[t] = true
	}

	// CSS: <link rel="stylesheet" href="...">
	if typeSet["css"] {
		cssRe := regexp.MustCompile(`<link[^>]+rel=["']?stylesheet["']?[^>]+href=["']([^"']+)["']|<link[^>]+href=["']([^"']+)["'][^>]+rel=["']?stylesheet["']?`)
		matches := cssRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			href := m[1]
			if href == "" {
				href = m[2]
			}
			if href != "" && !seen[href] {
				if absURL := p.resolveURL(href); absURL != "" {
					seen[href] = true
					resources = append(resources, resourceInfo{url: absURL, resType: "css"})
				}
			}
		}
	}

	// JavaScript: <script src="...">
	if typeSet["js"] {
		jsRe := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
		matches := jsRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if m[1] != "" && !seen[m[1]] {
				if absURL := p.resolveURL(m[1]); absURL != "" {
					seen[m[1]] = true
					resources = append(resources, resourceInfo{url: absURL, resType: "js"})
				}
			}
		}
	}

	// Images: <img src="...">, <img srcset="...">, <source srcset="...">, <picture><source>
	if typeSet["image"] {
		// Standard img src
		imgRe := regexp.MustCompile(`<img[^>]+src=["']([^"']+)["']`)
		matches := imgRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if m[1] != "" && !seen[m[1]] && !strings.HasPrefix(m[1], "data:") {
				if absURL := p.resolveURL(m[1]); absURL != "" {
					seen[m[1]] = true
					resources = append(resources, resourceInfo{url: absURL, resType: "image"})
				}
			}
		}

		// srcset images (take first URL from srcset)
		srcsetRe := regexp.MustCompile(`(?:img|source)[^>]+srcset=["']([^"']+)["']`)
		matches = srcsetRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if m[1] != "" {
				// Extract first URL from srcset (format: "url 1x, url2 2x")
				srcsetParts := strings.Split(m[1], ",")
				for _, part := range srcsetParts {
					part = strings.TrimSpace(part)
					urlPart := strings.Fields(part)
					if len(urlPart) > 0 && !seen[urlPart[0]] && !strings.HasPrefix(urlPart[0], "data:") {
						if absURL := p.resolveURL(urlPart[0]); absURL != "" {
							seen[urlPart[0]] = true
							resources = append(resources, resourceInfo{url: absURL, resType: "image"})
						}
					}
				}
			}
		}

		// Background images in style attributes
		bgRe := regexp.MustCompile(`style=["'][^"']*background(?:-image)?:\s*url\(['"]?([^'")\s]+)['"]?\)`)
		matches = bgRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if m[1] != "" && !seen[m[1]] && !strings.HasPrefix(m[1], "data:") {
				if absURL := p.resolveURL(m[1]); absURL != "" {
					seen[m[1]] = true
					resources = append(resources, resourceInfo{url: absURL, resType: "image"})
				}
			}
		}

		// Favicon
		faviconRe := regexp.MustCompile(`<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']|<link[^>]+href=["']([^"']+)["'][^>]+rel=["'](?:shortcut )?icon["']`)
		matches = faviconRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			href := m[1]
			if href == "" {
				href = m[2]
			}
			if href != "" && !seen[href] {
				if absURL := p.resolveURL(href); absURL != "" {
					seen[href] = true
					resources = append(resources, resourceInfo{url: absURL, resType: "image"})
				}
			}
		}
	}

	// Fonts: preload fonts
	if typeSet["font"] {
		fontRe := regexp.MustCompile(`<link[^>]+rel=["']?preload["']?[^>]+href=["']([^"']+)["'][^>]+as=["']?font["']?|<link[^>]+as=["']?font["']?[^>]+href=["']([^"']+)["']`)
		matches := fontRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			href := m[1]
			if href == "" {
				href = m[2]
			}
			if href != "" && !seen[href] {
				if absURL := p.resolveURL(href); absURL != "" {
					seen[href] = true
					resources = append(resources, resourceInfo{url: absURL, resType: "font"})
				}
			}
		}
	}

	// Links: <a href="..."> (only same-origin links)
	if typeSet["link"] {
		linkRe := regexp.MustCompile(`<a[^>]+href=["']([^"'#]+)["']`)
		matches := linkRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			href := m[1]
			if href != "" && !seen[href] && !strings.HasPrefix(href, "javascript:") && !strings.HasPrefix(href, "mailto:") {
				if absURL := p.resolveURL(href); absURL != "" {
					// Only include same-origin links
					parsedURL, err := url.Parse(absURL)
					if err == nil && parsedURL.Host == p.baseURL.Host {
						seen[href] = true
						resources = append(resources, resourceInfo{url: absURL, resType: "link"})
					}
				}
			}
		}
	}

	// Media: video, audio, source, iframe
	if typeSet["media"] {
		// Video src
		videoRe := regexp.MustCompile(`<video[^>]+src=["']([^"']+)["']`)
		matches := videoRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if m[1] != "" && !seen[m[1]] {
				if absURL := p.resolveURL(m[1]); absURL != "" {
					seen[m[1]] = true
					resources = append(resources, resourceInfo{url: absURL, resType: "media"})
				}
			}
		}

		// Audio src
		audioRe := regexp.MustCompile(`<audio[^>]+src=["']([^"']+)["']`)
		matches = audioRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if m[1] != "" && !seen[m[1]] {
				if absURL := p.resolveURL(m[1]); absURL != "" {
					seen[m[1]] = true
					resources = append(resources, resourceInfo{url: absURL, resType: "media"})
				}
			}
		}

		// Source elements (for video/audio)
		sourceRe := regexp.MustCompile(`<source[^>]+src=["']([^"']+)["']`)
		matches = sourceRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if m[1] != "" && !seen[m[1]] {
				if absURL := p.resolveURL(m[1]); absURL != "" {
					seen[m[1]] = true
					resources = append(resources, resourceInfo{url: absURL, resType: "media"})
				}
			}
		}

		// Iframe src
		iframeRe := regexp.MustCompile(`<iframe[^>]+src=["']([^"']+)["']`)
		matches = iframeRe.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if m[1] != "" && !seen[m[1]] && !strings.HasPrefix(m[1], "about:") {
				if absURL := p.resolveURL(m[1]); absURL != "" {
					seen[m[1]] = true
					resources = append(resources, resourceInfo{url: absURL, resType: "media"})
				}
			}
		}
	}

	return resources
}

// resolveURL converts relative URLs to absolute URLs
func (p *PageAnalyzer) resolveURL(href string) string {
	if href == "" {
		return ""
	}

	// Already absolute
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}

	// Protocol-relative
	if strings.HasPrefix(href, "//") {
		return p.baseURL.Scheme + ":" + href
	}

	// Resolve relative URL
	refURL, err := url.Parse(href)
	if err != nil {
		return ""
	}

	return p.baseURL.ResolveReference(refURL).String()
}

// fetchResource fetches a single resource and returns timing information
func (p *PageAnalyzer) fetchResource(ctx context.Context, resource resourceInfo) PageResource {
	result := PageResource{
		URL:  resource.url,
		Type: resource.resType,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", resource.url, nil)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}

	// Set headers
	req.Header.Set("User-Agent", p.cfg.HTTP.UserAgent)
	req.Header.Set("Accept-Language", p.cfg.HTTP.AcceptLanguage)
	req.Header.Set("Accept-Encoding", p.cfg.HTTP.AcceptEncoding)
	req.Header.Set("Referer", p.baseURL.String())

	start := time.Now()
	resp, err := p.client.Do(req)
	result.Duration = Duration{time.Since(start)}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	// Read and discard body to get accurate timing
	io.Copy(io.Discard, resp.Body)

	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
	result.StatusCode = resp.StatusCode
	result.Status = resp.Status
	result.ContentType = resp.Header.Get("Content-Type")
	result.ContentLength = resp.ContentLength

	if !result.Success {
		result.Error = resp.Status
	}

	return result
}
