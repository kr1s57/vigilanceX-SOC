package license

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// LicenseInfo contains the full license information
type LicenseInfo struct {
	LicenseKey   string    `json:"license_key"`
	CustomerName string    `json:"customer_name"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaxFirewalls int       `json:"max_firewalls"`
	Features     []string  `json:"features"`
	IsValid      bool      `json:"is_valid"`
	Status       string    `json:"status"` // active, expired, revoked, grace
}

// LicenseStatus represents the current license status for API responses
type LicenseStatus struct {
	Licensed      bool       `json:"licensed"`
	Status        string     `json:"status"`
	CustomerName  string     `json:"customer_name,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	DaysRemaining int        `json:"days_remaining,omitempty"`
	GraceMode     bool       `json:"grace_mode"`
	Features      []string   `json:"features"`
	HardwareID    string     `json:"hardware_id,omitempty"`
}

// LicenseConfig holds the configuration for the license client
type LicenseConfig struct {
	ServerURL     string
	LicenseKey    string // For auto-activation
	HeartbeatInt  time.Duration
	GracePeriod   time.Duration
	Enabled       bool
	StorePath     string
}

// Client manages license validation and heartbeat
type Client struct {
	serverURL   string
	httpClient  *http.Client
	store       *LicenseStore
	license     *LicenseInfo
	mu          sync.RWMutex
	lastCheck   time.Time
	gracePeriod time.Duration
	graceStart  time.Time
	inGrace     bool
	hardwareID  string
}

// ActivateRequest is sent to the license server
type ActivateRequest struct {
	LicenseKey string `json:"license_key"`
	HardwareID string `json:"hardware_id"`
}

// ActivateResponse is received from the license server
type ActivateResponse struct {
	Success bool         `json:"success"`
	License *LicenseInfo `json:"license,omitempty"`
	Error   string       `json:"error,omitempty"`
}

// ValidateRequest is sent for heartbeat validation
type ValidateRequest struct {
	LicenseKey string `json:"license_key"`
	HardwareID string `json:"hardware_id"`
}

// ValidateResponse is received from validation
type ValidateResponse struct {
	Valid     bool      `json:"valid"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	Features  []string  `json:"features"`
	Error     string    `json:"error,omitempty"`
}

// NewClient creates a new license client
func NewClient(cfg LicenseConfig) (*Client, error) {
	// Create store
	storePath := cfg.StorePath
	if storePath == "" {
		storePath = "/app/data/license.json"
	}

	store, err := NewLicenseStore(storePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create license store: %w", err)
	}

	gracePeriod := cfg.GracePeriod
	if gracePeriod == 0 {
		gracePeriod = 72 * time.Hour
	}

	hwid := store.GetHardwareID()
	slog.Info("License client initialized", "hardware_id", hwid)

	client := &Client{
		serverURL: cfg.ServerURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		store:       store,
		gracePeriod: gracePeriod,
		hardwareID:  hwid,
	}

	return client, nil
}

// LoadFromStore loads persisted license from disk
func (c *Client) LoadFromStore() error {
	stored, err := c.store.Load()
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.license = &LicenseInfo{
		LicenseKey:   stored.LicenseKey,
		CustomerName: stored.CustomerName,
		ExpiresAt:    stored.ExpiresAt,
		MaxFirewalls: stored.MaxFirewalls,
		Features:     stored.Features,
		IsValid:      stored.IsValid,
		Status:       stored.Status,
	}

	// Restore IsValid based on status if it was active
	if stored.Status == "active" && stored.ExpiresAt.After(time.Now()) {
		c.license.IsValid = true
	}

	c.lastCheck = stored.LastValidated

	// Check if we were in grace mode
	if !stored.GraceStart.IsZero() {
		c.graceStart = stored.GraceStart
		c.inGrace = time.Since(stored.GraceStart) < c.gracePeriod
	}

	slog.Info("License loaded from store",
		"customer", c.license.CustomerName,
		"expires", c.license.ExpiresAt,
		"status", c.license.Status)

	return nil
}

// Activate activates a license key with the server
func (c *Client) Activate(ctx context.Context, licenseKey string) error {
	req := ActivateRequest{
		LicenseKey: licenseKey,
		HardwareID: c.hardwareID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		c.serverURL+"/api/v1/license/activate", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to contact license server: %w", err)
	}
	defer resp.Body.Close()

	var activateResp ActivateResponse
	if err := json.NewDecoder(resp.Body).Decode(&activateResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !activateResp.Success {
		return fmt.Errorf("activation failed: %s", activateResp.Error)
	}

	// Store the license
	c.mu.Lock()
	c.license = activateResp.License
	c.license.LicenseKey = licenseKey // Store the license key (not echoed by server for security)
	c.license.IsValid = true          // Ensure license is marked as valid after successful activation
	c.lastCheck = time.Now()
	c.inGrace = false
	c.graceStart = time.Time{}
	c.mu.Unlock()

	// Persist to disk
	if err := c.persistLicense(); err != nil {
		slog.Error("Failed to persist license", "error", err)
	}

	slog.Info("License activated successfully",
		"customer", c.license.CustomerName,
		"expires", c.license.ExpiresAt)

	return nil
}

// Validate performs a heartbeat validation with the server
func (c *Client) Validate(ctx context.Context) (*LicenseStatus, error) {
	c.mu.RLock()
	if c.license == nil {
		c.mu.RUnlock()
		return &LicenseStatus{
			Licensed: false,
			Status:   "not_activated",
		}, nil
	}
	licenseKey := c.license.LicenseKey
	c.mu.RUnlock()

	req := ValidateRequest{
		LicenseKey: licenseKey,
		HardwareID: c.hardwareID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		c.serverURL+"/api/v1/license/validate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Network error - enter grace mode
		return c.enterGraceMode(fmt.Errorf("network error: %w", err))
	}
	defer resp.Body.Close()

	var validateResp ValidateResponse
	if err := json.NewDecoder(resp.Body).Decode(&validateResp); err != nil {
		return c.enterGraceMode(fmt.Errorf("decode error: %w", err))
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !validateResp.Valid {
		// License revoked or expired
		c.license.IsValid = false
		c.license.Status = validateResp.Status
		c.inGrace = false
		c.persistLicense()

		return &LicenseStatus{
			Licensed: false,
			Status:   validateResp.Status,
		}, nil
	}

	// Valid response - update license info
	c.license.IsValid = true
	c.license.Status = validateResp.Status
	c.license.ExpiresAt = validateResp.ExpiresAt
	c.license.Features = validateResp.Features
	c.lastCheck = time.Now()
	c.inGrace = false
	c.graceStart = time.Time{}

	c.persistLicense()

	return c.getStatusLocked(), nil
}

// Heartbeat performs a validation and returns error if license is invalid
func (c *Client) Heartbeat(ctx context.Context) error {
	status, err := c.Validate(ctx)
	if err != nil {
		return err
	}

	if !status.Licensed && !status.GraceMode {
		return fmt.Errorf("license invalid: %s", status.Status)
	}

	return nil
}

// GetStatus returns the current license status
func (c *Client) GetStatus() *LicenseStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.getStatusLocked()
}

// getStatusLocked returns status (must hold lock)
func (c *Client) getStatusLocked() *LicenseStatus {
	if c.license == nil {
		return &LicenseStatus{
			Licensed:   false,
			Status:     "not_activated",
			HardwareID: c.hardwareID,
		}
	}

	// Check grace mode expiry
	if c.inGrace {
		if time.Since(c.graceStart) > c.gracePeriod {
			c.inGrace = false
			c.license.IsValid = false
			c.license.Status = "grace_expired"
		}
	}

	status := &LicenseStatus{
		Licensed:     c.license.IsValid || c.inGrace,
		Status:       c.license.Status,
		CustomerName: c.license.CustomerName,
		ExpiresAt:    &c.license.ExpiresAt,
		GraceMode:    c.inGrace,
		Features:     c.license.Features,
		HardwareID:   c.hardwareID,
	}

	// Calculate days remaining
	if c.license.ExpiresAt.After(time.Now()) {
		status.DaysRemaining = int(time.Until(c.license.ExpiresAt).Hours() / 24)
	}

	return status
}

// IsLicensed returns true if there is a valid license or in grace period
func (c *Client) IsLicensed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.license == nil {
		return false
	}

	// Check grace period expiry
	if c.inGrace {
		return time.Since(c.graceStart) < c.gracePeriod
	}

	return c.license.IsValid
}

// HasFeature checks if a feature is available in the license
func (c *Client) HasFeature(feature string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.license == nil || !c.IsLicensed() {
		return false
	}

	for _, f := range c.license.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// GetLicenseKey returns the current license key
func (c *Client) GetLicenseKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.license == nil {
		return ""
	}
	return c.license.LicenseKey
}

// GetHardwareID returns the hardware ID
func (c *Client) GetHardwareID() string {
	return c.hardwareID
}

// enterGraceMode handles network failures by entering grace mode
func (c *Client) enterGraceMode(originalErr error) (*LicenseStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.license == nil {
		return &LicenseStatus{
			Licensed: false,
			Status:   "not_activated",
		}, originalErr
	}

	// Start grace period if not already started
	if !c.inGrace {
		c.inGrace = true
		c.graceStart = time.Now()
		c.license.Status = "grace"
		c.persistLicense()

		slog.Warn("License server unreachable, entering grace mode",
			"grace_period", c.gracePeriod,
			"error", originalErr)
	}

	// Check if grace period has expired
	if time.Since(c.graceStart) > c.gracePeriod {
		c.inGrace = false
		c.license.IsValid = false
		c.license.Status = "grace_expired"
		c.persistLicense()

		return &LicenseStatus{
			Licensed: false,
			Status:   "grace_expired",
		}, fmt.Errorf("grace period expired")
	}

	status := c.getStatusLocked()
	return status, nil
}

// persistLicense saves the current license to disk
func (c *Client) persistLicense() error {
	if c.license == nil {
		return nil
	}

	stored := &StoredLicense{
		LicenseKey:    c.license.LicenseKey,
		CustomerName:  c.license.CustomerName,
		ExpiresAt:     c.license.ExpiresAt,
		MaxFirewalls:  c.license.MaxFirewalls,
		Features:      c.license.Features,
		IsValid:       c.license.IsValid,
		Status:        c.license.Status,
		HardwareID:    c.hardwareID,
		LastValidated: c.lastCheck,
		GraceStart:    c.graceStart,
	}

	return c.store.Save(stored)
}
