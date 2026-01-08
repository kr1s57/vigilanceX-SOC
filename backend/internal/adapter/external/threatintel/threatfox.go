package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ThreatFoxClient queries abuse.ch ThreatFox API for IOC data
// Free API - no authentication required
// Tier 1 provider (unlimited)
type ThreatFoxClient struct {
	httpClient *http.Client
	baseURL    string
}

// ThreatFoxResponse represents the API response
type ThreatFoxResponse struct {
	QueryStatus string           `json:"query_status"`
	Data        []ThreatFoxIOC   `json:"data"`
}

// ThreatFoxIOC represents an indicator of compromise
type ThreatFoxIOC struct {
	ID              string   `json:"id"`
	IOC             string   `json:"ioc"`
	IOCType         string   `json:"ioc_type"`
	ThreatType      string   `json:"threat_type"`
	ThreatTypeDesc  string   `json:"threat_type_desc"`
	Malware         string   `json:"malware"`
	MalwarePrintable string  `json:"malware_printable"`
	MalwareMalpedia string   `json:"malware_malpedia"`
	Confidence      int      `json:"confidence_level"`
	FirstSeen       string   `json:"first_seen"`
	LastSeen        string   `json:"last_seen"`
	Reporter        string   `json:"reporter"`
	Reference       string   `json:"reference"`
	Tags            []string `json:"tags"`
}

// ThreatFoxResult represents the processed result
type ThreatFoxResult struct {
	Found           bool     `json:"found"`
	ThreatType      string   `json:"threat_type,omitempty"`
	Malware         string   `json:"malware,omitempty"`
	MalwareFamily   string   `json:"malware_family,omitempty"`
	Confidence      int      `json:"confidence,omitempty"`
	FirstSeen       string   `json:"first_seen,omitempty"`
	LastSeen        string   `json:"last_seen,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	IOCCount        int      `json:"ioc_count,omitempty"`
	Score           int      `json:"score"`
	Reference       string   `json:"reference,omitempty"`
}

// NewThreatFoxClient creates a new ThreatFox client
func NewThreatFoxClient() *ThreatFoxClient {
	return &ThreatFoxClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		baseURL: "https://threatfox-api.abuse.ch/api/v1/",
	}
}

// IsConfigured returns true (ThreatFox is always available - no API key needed)
func (c *ThreatFoxClient) IsConfigured() bool {
	return true
}

// GetTier returns the provider tier (1 = unlimited)
func (c *ThreatFoxClient) GetTier() int {
	return 1
}

// CheckIP queries ThreatFox for an IP address
func (c *ThreatFoxClient) CheckIP(ctx context.Context, ip string) (*ThreatFoxResult, error) {
	// Search for IP as IOC
	payload := map[string]string{
		"query":       "search_ioc",
		"search_term": ip,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var tfResp ThreatFoxResponse
	if err := json.NewDecoder(resp.Body).Decode(&tfResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.processResponse(&tfResp), nil
}

// processResponse converts ThreatFox response to our result format
func (c *ThreatFoxClient) processResponse(resp *ThreatFoxResponse) *ThreatFoxResult {
	result := &ThreatFoxResult{
		Found: false,
		Score: 0,
	}

	if resp.QueryStatus != "ok" || len(resp.Data) == 0 {
		return result
	}

	result.Found = true
	result.IOCCount = len(resp.Data)

	// Use the most recent/relevant IOC
	ioc := resp.Data[0]
	result.ThreatType = ioc.ThreatType
	result.Malware = ioc.MalwarePrintable
	result.MalwareFamily = ioc.Malware
	result.Confidence = ioc.Confidence
	result.FirstSeen = ioc.FirstSeen
	result.LastSeen = ioc.LastSeen
	result.Reference = ioc.Reference

	// Collect all unique tags
	tagSet := make(map[string]bool)
	for _, d := range resp.Data {
		for _, tag := range d.Tags {
			tagSet[strings.ToLower(tag)] = true
		}
	}
	for tag := range tagSet {
		result.Tags = append(result.Tags, tag)
	}

	// Calculate score based on threat type and confidence
	result.Score = c.calculateScore(resp.Data)

	return result
}

// calculateScore calculates a threat score based on IOCs found
func (c *ThreatFoxClient) calculateScore(iocs []ThreatFoxIOC) int {
	if len(iocs) == 0 {
		return 0
	}

	// Base score for being in ThreatFox at all
	score := 60

	// Get highest confidence
	maxConfidence := 0
	for _, ioc := range iocs {
		if ioc.Confidence > maxConfidence {
			maxConfidence = ioc.Confidence
		}
	}

	// Adjust score based on confidence (0-100)
	score += maxConfidence / 5 // +0 to +20

	// Adjust based on threat type
	for _, ioc := range iocs {
		switch strings.ToLower(ioc.ThreatType) {
		case "botnet_cc", "cc":
			score += 15 // C2 servers are critical
		case "payload_delivery":
			score += 10
		case "payload":
			score += 5
		}
	}

	// More IOCs = more confidence
	if len(iocs) > 1 {
		score += min(len(iocs)*2, 10)
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}
