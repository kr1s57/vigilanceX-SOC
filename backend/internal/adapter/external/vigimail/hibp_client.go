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
	hibpBaseURL   = "https://haveibeenpwned.com/api/v3"
	hibpRateLimit = 1500 * time.Millisecond // 1 request per 1.5 seconds with paid API key
	hibpUserAgent = "VIGILANCE-X-SOC"
)

// HIBPClient is the HaveIBeenPwned API client
type HIBPClient struct {
	httpClient *http.Client
	apiKey     string
	mu         sync.RWMutex
	lastCall   time.Time
}

// HIBPBreach represents a breach from HIBP API
type HIBPBreach struct {
	Name         string   `json:"Name"`
	Title        string   `json:"Title"`
	Domain       string   `json:"Domain"`
	BreachDate   string   `json:"BreachDate"`
	AddedDate    string   `json:"AddedDate"`
	ModifiedDate string   `json:"ModifiedDate"`
	PwnCount     int      `json:"PwnCount"`
	Description  string   `json:"Description"`
	DataClasses  []string `json:"DataClasses"`
	IsVerified   bool     `json:"IsVerified"`
	IsFabricated bool     `json:"IsFabricated"`
	IsSensitive  bool     `json:"IsSensitive"`
	IsRetired    bool     `json:"IsRetired"`
	IsSpamList   bool     `json:"IsSpamList"`
}

// NewHIBPClient creates a new HIBP client
func NewHIBPClient(apiKey string) *HIBPClient {
	return &HIBPClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiKey: apiKey,
	}
}

// SetAPIKey updates the API key
func (c *HIBPClient) SetAPIKey(apiKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiKey = apiKey
}

// GetAPIKey returns the current API key
func (c *HIBPClient) GetAPIKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey
}

// IsConfigured returns true if API key is set
func (c *HIBPClient) IsConfigured() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey != ""
}

// rateLimitWait waits for rate limit if needed
func (c *HIBPClient) rateLimitWait() {
	c.mu.Lock()
	defer c.mu.Unlock()

	elapsed := time.Since(c.lastCall)
	if elapsed < hibpRateLimit {
		time.Sleep(hibpRateLimit - elapsed)
	}
	c.lastCall = time.Now()
}

// CheckEmail checks an email for breaches
func (c *HIBPClient) CheckEmail(ctx context.Context, email string) ([]entity.VigimailLeak, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("HIBP API key not configured")
	}

	// Rate limit
	c.rateLimitWait()

	// Build URL
	encodedEmail := url.PathEscape(strings.ToLower(email))
	reqURL := fmt.Sprintf("%s/breachedaccount/%s?truncateResponse=false", hibpBaseURL, encodedEmail)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	c.mu.RLock()
	req.Header.Set("hibp-api-key", c.apiKey)
	c.mu.RUnlock()
	req.Header.Set("User-Agent", hibpUserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Has breaches
		var breaches []HIBPBreach
		if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}

		leaks := make([]entity.VigimailLeak, 0, len(breaches))
		for _, b := range breaches {
			leak := entity.VigimailLeak{
				Email:       strings.ToLower(email),
				Source:      "hibp",
				BreachName:  b.Name,
				DataClasses: b.DataClasses,
				IsVerified:  b.IsVerified,
				IsSensitive: b.IsSensitive,
				Description: b.Description,
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
			}
			if b.BreachDate != "" {
				leak.BreachDate = &b.BreachDate
			}
			leaks = append(leaks, leak)
		}

		slog.Info("[HIBP] Found breaches", "email", email, "count", len(leaks))
		return leaks, nil

	case http.StatusNotFound:
		// No breaches found - this is good!
		slog.Debug("[HIBP] No breaches found", "email", email)
		return []entity.VigimailLeak{}, nil

	case http.StatusUnauthorized:
		return nil, fmt.Errorf("invalid API key")

	case http.StatusForbidden:
		return nil, fmt.Errorf("API key not authorized for this operation")

	case http.StatusTooManyRequests:
		// Rate limited - should not happen with proper wait
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rate limited: %s", string(body))

	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

// TestConnection verifies the API key works
func (c *HIBPClient) TestConnection(ctx context.Context) error {
	if !c.IsConfigured() {
		return fmt.Errorf("API key not configured")
	}

	// Test with a known safe email
	req, err := http.NewRequestWithContext(ctx, "GET", hibpBaseURL+"/breaches", nil)
	if err != nil {
		return err
	}

	c.mu.RLock()
	req.Header.Set("hibp-api-key", c.apiKey)
	c.mu.RUnlock()
	req.Header.Set("User-Agent", hibpUserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid API key")
	}

	return fmt.Errorf("unexpected status: %d", resp.StatusCode)
}

// GetBreachDetails retrieves details about a specific breach
func (c *HIBPClient) GetBreachDetails(ctx context.Context, breachName string) (*HIBPBreach, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", hibpBaseURL+"/breach/"+url.PathEscape(breachName), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", hibpUserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("breach not found")
	}

	var breach HIBPBreach
	if err := json.NewDecoder(resp.Body).Decode(&breach); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &breach, nil
}
