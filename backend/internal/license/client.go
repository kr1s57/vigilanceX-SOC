package license

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
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
	// v3.0: Firewall binding info
	BindingVersion string `json:"binding_version,omitempty"` // VX2 or VX3
	FirewallSerial string `json:"firewall_serial,omitempty"`
	FirewallModel  string `json:"firewall_model,omitempty"`
	FirewallName   string `json:"firewall_name,omitempty"`
	SecureBinding  bool   `json:"secure_binding"` // true if VX3 binding is active
	// v3.2: Fresh Deploy info
	DeploymentType   string `json:"deployment_type,omitempty"` // manual or fresh_deploy
	FirewallDetected bool   `json:"firewall_detected"`
	AskProAvailable  bool   `json:"ask_pro_available"`
}

// LicenseConfig holds the configuration for the license client
type LicenseConfig struct {
	ServerURL    string
	LicenseKey   string // For auto-activation
	HeartbeatInt time.Duration
	GracePeriod  time.Duration
	Enabled      bool
	StorePath    string
	// v3.0: Database info for firewall binding
	Database     string    // ClickHouse database name
	DBConnection DBQuerier // ClickHouse connection (optional)
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
	// v3.0: Include firewall info for server-side validation
	FirewallSerial string `json:"firewall_serial,omitempty"`
	FirewallModel  string `json:"firewall_model,omitempty"`
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
	// v3.0: Include firewall info for server-side verification
	FirewallSerial string `json:"firewall_serial,omitempty"`
}

// ValidateResponse is received from validation
type ValidateResponse struct {
	Valid     bool      `json:"valid"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	Features  []string  `json:"features"`
	Error     string    `json:"error,omitempty"`
}

// FreshDeployRequest is sent to register a trial license (v3.2)
type FreshDeployRequest struct {
	Email    string `json:"email"`
	VMID     string `json:"vmid"`
	Hostname string `json:"hostname,omitempty"`
}

// FreshDeployResponse is received from fresh deploy registration
type FreshDeployResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	License *struct {
		Licensed         bool      `json:"licensed"`
		Status           string    `json:"status"`
		CustomerName     string    `json:"customer_name,omitempty"`
		ExpiresAt        time.Time `json:"expires_at,omitempty"`
		DaysRemaining    int       `json:"days_remaining,omitempty"`
		Features         []string  `json:"features,omitempty"`
		LicenseKey       string    `json:"license_key,omitempty"` // v3.55.114: Added to receive key from VGXKey
		DeploymentType   string    `json:"deployment_type,omitempty"`
		FirewallDetected bool      `json:"firewall_detected"`
		AskProAvailable  bool      `json:"ask_pro_available"`
	} `json:"license,omitempty"`
}

// FirewallUpdateRequest is sent to update firewall binding (v3.2)
type FirewallUpdateRequest struct {
	LicenseKey     string `json:"license_key"`
	HardwareID     string `json:"hardware_id"`
	FirewallSerial string `json:"firewall_serial"`
	FirewallModel  string `json:"firewall_model,omitempty"`
	FirewallName   string `json:"firewall_name,omitempty"`
}

// FirewallUpdateResponse is received from firewall update
type FirewallUpdateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	License *struct {
		Status           string `json:"status"`
		FirewallDetected bool   `json:"firewall_detected"`
		AskProAvailable  bool   `json:"ask_pro_available"`
	} `json:"license,omitempty"`
	Error string `json:"error,omitempty"`
}

// AskProRequest is sent to request pro license upgrade (v3.2)
type AskProRequest struct {
	LicenseKey string `json:"license_key"`
	HardwareID string `json:"hardware_id"`
}

// AskProResponse is received from ask pro request
type AskProResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	License *struct {
		Status          string `json:"status"`
		AskProAvailable bool   `json:"ask_pro_available"`
	} `json:"license,omitempty"`
	Error string `json:"error,omitempty"`
}

// createHTTPClient creates an HTTP client with optional TLS skip verification
func createHTTPClient() *http.Client {
	transport := &http.Transport{}

	// Check for insecure skip verify (for self-signed certs with IP addresses)
	if os.Getenv("LICENSE_INSECURE_SKIP_VERIFY") == "true" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		slog.Warn("License client using InsecureSkipVerify for TLS (self-signed cert mode)")
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

// NewClient creates a new license client (legacy - without firewall binding)
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
		gracePeriod = 168 * time.Hour // v3.0: Default to 7 days
	}

	hwid := store.GetHardwareID()
	slog.Info("License client initialized (legacy VX2)",
		"hardware_id", hwid[:16]+"...",
		"binding", "VX2")

	client := &Client{
		serverURL:   cfg.ServerURL,
		httpClient:  createHTTPClient(),
		store:       store,
		gracePeriod: gracePeriod,
		hardwareID:  hwid,
	}

	return client, nil
}

// NewClientWithFirewall creates a license client with firewall binding (v3.0)
func NewClientWithFirewall(ctx context.Context, cfg LicenseConfig) (*Client, error) {
	storePath := cfg.StorePath
	if storePath == "" {
		storePath = "/app/data/license.json"
	}

	database := cfg.Database
	if database == "" {
		database = "vigilance_x"
	}

	// Create store with firewall binding
	store, err := NewLicenseStoreWithFirewall(ctx, storePath, cfg.DBConnection, database)
	if err != nil {
		// Fall back to legacy store if firewall binding fails
		slog.Warn("Failed to create store with firewall binding, falling back to legacy",
			"error", err)
		return NewClient(cfg)
	}

	gracePeriod := cfg.GracePeriod
	if gracePeriod == 0 {
		gracePeriod = 168 * time.Hour // v3.0: Default to 7 days
	}

	hwid := store.GetHardwareID()
	bindingType := "VX2"
	if store.HasSecureBinding() {
		bindingType = "VX3"
	}

	fwInfo := store.GetFirewallInfo()
	if fwInfo != nil {
		slog.Info("License client initialized with firewall binding",
			"hardware_id", hwid[:16]+"...",
			"binding", bindingType,
			"firewall_serial", fwInfo.Serial,
			"firewall_model", fwInfo.Model)
	} else {
		slog.Info("License client initialized (no firewall detected yet)",
			"hardware_id", hwid[:16]+"...",
			"binding", bindingType)
	}

	client := &Client{
		serverURL:   cfg.ServerURL,
		httpClient:  createHTTPClient(),
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

	// Restore IsValid based on status if license is valid
	// v3.55.113: Fix - support trial statuses (FDEPLOY, TRIAL, trial, etc.) not just "active"
	statusLower := strings.ToLower(stored.Status)
	validStatuses := map[string]bool{
		"active":  true,
		"trial":   true,
		"fdeploy": true,
		"asked":   true, // Asked for Pro - still valid trial
	}
	if validStatuses[statusLower] && stored.ExpiresAt.After(time.Now()) {
		c.license.IsValid = true
	}

	c.lastCheck = stored.LastValidated

	// Check if we were in grace mode
	if !stored.GraceStart.IsZero() {
		c.graceStart = stored.GraceStart
		c.inGrace = time.Since(stored.GraceStart) < c.gracePeriod
	}

	bindingInfo := ""
	if stored.BindingVersion == "VX3" {
		bindingInfo = fmt.Sprintf(" (VX3: %s)", stored.FirewallSerial)
	}

	slog.Info("License loaded from store",
		"customer", c.license.CustomerName,
		"expires", c.license.ExpiresAt,
		"status", c.license.Status,
		"binding", stored.BindingVersion+bindingInfo)

	return nil
}

// Activate activates a license key with the server
func (c *Client) Activate(ctx context.Context, licenseKey string) error {
	fwInfo := c.store.GetFirewallInfo()

	req := ActivateRequest{
		LicenseKey: licenseKey,
		HardwareID: c.hardwareID,
	}

	// v3.0: Include firewall info if available
	if fwInfo != nil {
		req.FirewallSerial = fwInfo.Serial
		req.FirewallModel = fwInfo.Model
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
	c.license.LicenseKey = licenseKey
	c.license.IsValid = true
	c.lastCheck = time.Now()
	c.inGrace = false
	c.graceStart = time.Time{}
	c.mu.Unlock()

	// Persist to disk
	if err := c.persistLicense(); err != nil {
		slog.Error("Failed to persist license", "error", err)
	}

	bindingType := "VX2"
	if c.store.HasSecureBinding() {
		bindingType = "VX3"
	}

	slog.Info("License activated successfully",
		"customer", c.license.CustomerName,
		"expires", c.license.ExpiresAt,
		"binding", bindingType)

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

	fwInfo := c.store.GetFirewallInfo()

	req := ValidateRequest{
		LicenseKey: licenseKey,
		HardwareID: c.hardwareID,
	}

	// v3.0: Include firewall serial for verification
	if fwInfo != nil {
		req.FirewallSerial = fwInfo.Serial
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
		status := &LicenseStatus{
			Licensed:   false,
			Status:     "not_activated",
			HardwareID: c.hardwareID,
		}
		c.addFirewallInfoToStatus(status)
		return status
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

	// v3.0: Add firewall binding info
	c.addFirewallInfoToStatus(status)

	return status
}

// addFirewallInfoToStatus adds firewall binding information to the status
func (c *Client) addFirewallInfoToStatus(status *LicenseStatus) {
	if c.store.HasSecureBinding() {
		status.BindingVersion = "VX3"
		status.SecureBinding = true
		if fwInfo := c.store.GetFirewallInfo(); fwInfo != nil {
			status.FirewallSerial = fwInfo.Serial
			status.FirewallModel = fwInfo.Model
			status.FirewallName = fwInfo.Name
		}
	} else {
		status.BindingVersion = "VX2"
		status.SecureBinding = false
	}
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

// HasSecureBinding returns true if using VX3 firewall binding
func (c *Client) HasSecureBinding() bool {
	return c.store.HasSecureBinding()
}

// GetFirewallInfo returns the bound firewall information
func (c *Client) GetFirewallInfo() *FirewallInfo {
	return c.store.GetFirewallInfo()
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

// ==================== v3.2 Fresh Deploy Methods ====================

// NeedsFreshDeploy returns true if no valid license is configured and fresh deploy is possible
func (c *Client) NeedsFreshDeploy() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// No license at all
	if c.license == nil {
		return true
	}

	// License exists but is invalid/expired/revoked - allow fresh deploy
	status := c.license.Status
	return status == "invalid" || status == "expired" || status == "revoked" || status == "not_activated" || status == ""
}

// HasFirewallDetected returns true if a firewall has been detected and bound
func (c *Client) HasFirewallDetected() bool {
	return c.store.HasSecureBinding() && c.store.GetFirewallInfo() != nil
}

// FreshDeploy registers a new trial license with the server
func (c *Client) FreshDeploy(ctx context.Context, email, hostname string) (*FreshDeployResponse, error) {
	req := FreshDeployRequest{
		Email:    email,
		VMID:     c.hardwareID,
		Hostname: hostname,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		c.serverURL+"/api/v1/license/fresh-deploy", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to contact license server: %w", err)
	}
	defer resp.Body.Close()

	var freshResp FreshDeployResponse
	if err := json.NewDecoder(resp.Body).Decode(&freshResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !freshResp.Success {
		return &freshResp, fmt.Errorf("fresh deploy failed: %s", freshResp.Error)
	}

	// Store the trial license info
	if freshResp.License != nil {
		c.mu.Lock()
		c.license = &LicenseInfo{
			LicenseKey:   freshResp.License.LicenseKey, // v3.55.114: Store the key from VGXKey
			CustomerName: freshResp.License.CustomerName,
			ExpiresAt:    freshResp.License.ExpiresAt,
			Features:     freshResp.License.Features,
			IsValid:      freshResp.License.Licensed,
			Status:       freshResp.License.Status,
		}
		c.lastCheck = time.Now()
		c.mu.Unlock()

		// Persist to disk
		if err := c.persistLicense(); err != nil {
			slog.Error("Failed to persist trial license", "error", err)
		}

		slog.Info("Trial license registered",
			"license_key", freshResp.License.LicenseKey,
			"status", freshResp.License.Status,
			"days_remaining", freshResp.License.DaysRemaining)
	}

	return &freshResp, nil
}

// UpdateFirewallBinding sends firewall information to the license server
func (c *Client) UpdateFirewallBinding(ctx context.Context) (*FirewallUpdateResponse, error) {
	c.mu.RLock()
	if c.license == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("no license configured")
	}
	licenseKey := c.license.LicenseKey
	c.mu.RUnlock()

	fwInfo := c.store.GetFirewallInfo()
	if fwInfo == nil {
		return nil, fmt.Errorf("no firewall detected")
	}

	req := FirewallUpdateRequest{
		LicenseKey:     licenseKey,
		HardwareID:     c.hardwareID,
		FirewallSerial: fwInfo.Serial,
		FirewallModel:  fwInfo.Model,
		FirewallName:   fwInfo.Name,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "PUT",
		c.serverURL+"/api/v1/license/firewall", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to contact license server: %w", err)
	}
	defer resp.Body.Close()

	var updateResp FirewallUpdateResponse
	if err := json.NewDecoder(resp.Body).Decode(&updateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !updateResp.Success {
		return &updateResp, fmt.Errorf("firewall update failed: %s", updateResp.Error)
	}

	// Update license status if provided
	if updateResp.License != nil {
		c.mu.Lock()
		c.license.Status = updateResp.License.Status
		c.mu.Unlock()
		c.persistLicense()

		slog.Info("Firewall binding updated",
			"status", updateResp.License.Status,
			"firewall", fwInfo.Serial)
	}

	return &updateResp, nil
}

// AskProLicense requests a pro license upgrade
func (c *Client) AskProLicense(ctx context.Context) (*AskProResponse, error) {
	c.mu.RLock()
	if c.license == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("no license configured")
	}
	licenseKey := c.license.LicenseKey
	c.mu.RUnlock()

	req := AskProRequest{
		LicenseKey: licenseKey,
		HardwareID: c.hardwareID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		c.serverURL+"/api/v1/license/ask-pro", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to contact license server: %w", err)
	}
	defer resp.Body.Close()

	var askResp AskProResponse
	if err := json.NewDecoder(resp.Body).Decode(&askResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !askResp.Success {
		return &askResp, fmt.Errorf("ask pro failed: %s", askResp.Error)
	}

	// Update license status if provided
	if askResp.License != nil {
		c.mu.Lock()
		c.license.Status = askResp.License.Status
		c.mu.Unlock()
		c.persistLicense()

		slog.Info("Pro license requested",
			"status", askResp.License.Status)
	}

	return &askResp, nil
}
