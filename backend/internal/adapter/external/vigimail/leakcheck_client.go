package vigimail

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

const (
	leakcheckBaseURL   = "https://leakcheck.io/api/public"
	leakcheckRateLimit = 6 * time.Second // Conservative rate limit for free tier
)

// LeakCheckClient is the LeakCheck.io API client
type LeakCheckClient struct {
	httpClient *http.Client
	apiKey     string // Optional - for paid tier
	mu         sync.RWMutex
	lastCall   time.Time
}

// LeakCheckResponse represents the API response
type LeakCheckResponse struct {
	Success bool              `json:"success"`
	Found   int               `json:"found"`
	Fields  []string          `json:"fields,omitempty"`
	Sources []LeakCheckSource `json:"sources,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// LeakCheckSource represents a source/breach in LeakCheck
type LeakCheckSource struct {
	Name   string   `json:"name"`
	Date   string   `json:"date,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

// NewLeakCheckClient creates a new LeakCheck client
func NewLeakCheckClient(apiKey string) *LeakCheckClient {
	return &LeakCheckClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiKey: apiKey,
	}
}

// SetAPIKey updates the API key
func (c *LeakCheckClient) SetAPIKey(apiKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiKey = apiKey
}

// GetAPIKey returns the current API key
func (c *LeakCheckClient) GetAPIKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey
}

// IsConfigured returns true (LeakCheck works without API key for basic usage)
func (c *LeakCheckClient) IsConfigured() bool {
	return true // Public API available without key
}

// rateLimitWait waits for rate limit if needed
func (c *LeakCheckClient) rateLimitWait() {
	c.mu.Lock()
	defer c.mu.Unlock()

	elapsed := time.Since(c.lastCall)
	if elapsed < leakcheckRateLimit {
		time.Sleep(leakcheckRateLimit - elapsed)
	}
	c.lastCall = time.Now()
}

// CheckEmail checks an email for leaks
func (c *LeakCheckClient) CheckEmail(ctx context.Context, email string) ([]entity.VigimailLeak, error) {
	// Rate limit
	c.rateLimitWait()

	// Build URL
	reqURL := fmt.Sprintf("%s?check=%s", leakcheckBaseURL, url.QueryEscape(strings.ToLower(email)))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Add API key if available (for higher limits)
	c.mu.RLock()
	if c.apiKey != "" {
		req.Header.Set("X-Api-Key", c.apiKey)
	}
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result LeakCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if !result.Success {
		if result.Error != "" {
			// Rate limit or other error
			if strings.Contains(result.Error, "limit") {
				return nil, fmt.Errorf("rate limited: %s", result.Error)
			}
			return nil, fmt.Errorf("API error: %s", result.Error)
		}
		// No leaks found
		slog.Debug("[LEAKCHECK] No leaks found", "email", email)
		return []entity.VigimailLeak{}, nil
	}

	if result.Found == 0 || len(result.Sources) == 0 {
		slog.Debug("[LEAKCHECK] No leaks found", "email", email)
		return []entity.VigimailLeak{}, nil
	}

	leaks := make([]entity.VigimailLeak, 0, len(result.Sources))
	for _, src := range result.Sources {
		leak := entity.VigimailLeak{
			Email:       strings.ToLower(email),
			Source:      "leakcheck",
			BreachName:  src.Name,
			DataClasses: src.Fields,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		}

		if src.Date != "" {
			leak.BreachDate = &src.Date
		}

		// Determine if sensitive based on data classes
		for _, field := range src.Fields {
			if strings.Contains(strings.ToLower(field), "password") ||
				strings.Contains(strings.ToLower(field), "credit") ||
				strings.Contains(strings.ToLower(field), "ssn") {
				leak.IsSensitive = true
				break
			}
		}

		leaks = append(leaks, leak)
	}

	slog.Info("[LEAKCHECK] Found leaks", "email", email, "count", len(leaks))
	return leaks, nil
}

// TestConnection verifies the API is reachable
func (c *LeakCheckClient) TestConnection(ctx context.Context) error {
	// Test with a simple request
	req, err := http.NewRequestWithContext(ctx, "GET", leakcheckBaseURL, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	// Even without params, the API should respond
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest {
		return nil // API is reachable
	}

	return fmt.Errorf("unexpected status: %d", resp.StatusCode)
}
