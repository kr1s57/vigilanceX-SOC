package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kr1s57/vigilancex/internal/entity"
	"golang.org/x/crypto/ssh"
)

// SMTPReloadFunc is a callback to reload SMTP configuration
type SMTPReloadFunc func(host string, port int, security, fromEmail, username, password string, recipients []string)

// SystemWhitelistRepository interface for custom entries
type SystemWhitelistRepository interface {
	List(ctx context.Context) ([]entity.CustomSystemWhitelistEntry, error)
	GetByIP(ctx context.Context, ip string) (*entity.CustomSystemWhitelistEntry, error)
	Create(ctx context.Context, entry *entity.CustomSystemWhitelistEntry) error
	Update(ctx context.Context, entry *entity.CustomSystemWhitelistEntry) error
	Delete(ctx context.Context, id string) error
}

// ConfigHandler handles configuration management
type ConfigHandler struct {
	configPath       string
	mu               sync.RWMutex
	onSMTPReload     SMTPReloadFunc
	sysWhitelistRepo SystemWhitelistRepository
}

// NewConfigHandler creates a new config handler
func NewConfigHandler() *ConfigHandler {
	return &ConfigHandler{
		configPath: "/app/config/integrations.json",
	}
}

// SetSystemWhitelistRepo sets the system whitelist repository for CRUD operations
func (h *ConfigHandler) SetSystemWhitelistRepo(repo SystemWhitelistRepository) {
	h.sysWhitelistRepo = repo
}

// SetSMTPReloadCallback sets the callback for SMTP config reload
func (h *ConfigHandler) SetSMTPReloadCallback(fn SMTPReloadFunc) {
	h.onSMTPReload = fn
}

// IntegrationConfig represents a single integration configuration
type IntegrationConfig struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Fields    map[string]string `json:"fields"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// ConfigTestRequest represents a request to test configuration
type ConfigTestRequest struct {
	PluginID string            `json:"plugin_id"`
	Fields   map[string]string `json:"fields"`
}

// ConfigTestResponse represents the test result
type ConfigTestResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Status  string `json:"status"` // "connected", "failed", "invalid"
}

// TestConfig tests a configuration without saving
// POST /api/v1/config/test
func (h *ConfigHandler) TestConfig(w http.ResponseWriter, r *http.Request) {
	var req ConfigTestRequest
	if err := DecodeJSON(r, &req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	result := h.testIntegration(req.PluginID, req.Fields)
	JSONResponse(w, http.StatusOK, result)
}

// SaveConfig saves and tests configuration
// POST /api/v1/config/save
func (h *ConfigHandler) SaveConfig(w http.ResponseWriter, r *http.Request) {
	var req ConfigTestRequest
	if err := DecodeJSON(r, &req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// First test the configuration
	testResult := h.testIntegration(req.PluginID, req.Fields)

	// Save regardless of test result (user might want to save for later)
	if err := h.saveIntegrationConfig(req.PluginID, req.Fields); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to save configuration", err)
		return
	}

	// Update environment variables in memory for immediate effect
	h.applyConfigToEnv(req.PluginID, req.Fields)

	// Hot-reload SMTP client if SMTP config was saved
	if req.PluginID == "smtp" && h.onSMTPReload != nil {
		// Load the merged config to get all fields including preserved passwords
		mergedConfig := h.getMergedConfig(req.PluginID, req.Fields)

		port := 587
		if p := mergedConfig["SMTP_PORT"]; p != "" {
			fmt.Sscanf(p, "%d", &port)
		}
		recipients := strings.Split(mergedConfig["SMTP_RECIPIENTS"], ",")
		for i := range recipients {
			recipients[i] = strings.TrimSpace(recipients[i])
		}
		h.onSMTPReload(
			mergedConfig["SMTP_HOST"],
			port,
			mergedConfig["SMTP_SECURITY"],
			mergedConfig["SMTP_FROM_EMAIL"],
			mergedConfig["SMTP_USERNAME"],
			mergedConfig["SMTP_PASSWORD"],
			recipients,
		)
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"saved":   true,
		"test":    testResult,
		"message": "Configuration saved. " + testResult.Message,
	})
}

// shouldMaskField determines if a config field value should be masked
// Returns true for sensitive fields like API keys and passwords
// Returns false for non-sensitive fields like key paths
func shouldMaskField(key string) bool {
	lowerKey := strings.ToLower(key)

	// Explicit non-sensitive fields (file paths, etc.)
	nonSensitivePatterns := []string{
		"_path", // SSH_KEY_PATH, etc.
		"_file", // key file locations
		"_dir",  // directories
	}
	for _, pattern := range nonSensitivePatterns {
		if strings.Contains(lowerKey, pattern) {
			return false
		}
	}

	// Sensitive field patterns
	sensitivePatterns := []string{
		"password",
		"api_key",
		"apikey",
		"secret",
		"token",
	}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerKey, pattern) {
			return true
		}
	}

	// Special case: field named exactly "key" (like CrowdSec CTI key)
	// but not fields that contain "key" as part of another word like "SSH_KEY_PATH"
	if lowerKey == "key" || strings.HasSuffix(lowerKey, "_key") {
		return true
	}

	return false
}

// GetConfig retrieves saved configuration
// GET /api/v1/config/{plugin_id}
func (h *ConfigHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	// Return masked config (don't expose full API keys)
	configs := h.loadAllConfigs()
	maskedConfigs := make(map[string]map[string]string)

	// First, add configs from integrations.json
	for id, config := range configs {
		maskedConfigs[id] = make(map[string]string)
		for key, value := range config.Fields {
			if shouldMaskField(key) {
				if len(value) > 4 {
					maskedConfigs[id][key] = value[:4] + "****"
				} else if len(value) > 0 {
					maskedConfigs[id][key] = "****"
				} else {
					maskedConfigs[id][key] = ""
				}
			} else {
				maskedConfigs[id][key] = value
			}
		}
	}

	// v3.53.105: Also check environment variables for plugins not in integrations.json
	// This allows Disconnect button to work for plugins configured via .env
	envPlugins := map[string][]string{
		"abuseipdb":     {"ABUSEIPDB_API_KEY"},
		"virustotal":    {"VIRUSTOTAL_API_KEY"},
		"alienvault":    {"ALIENVAULT_API_KEY"},
		"greynoise":     {"GREYNOISE_API_KEY"},
		"crowdsec":      {"CROWDSEC_API_KEY"},
		"criminalip":    {"CRIMINALIP_API_KEY"},
		"pulsedive":     {"PULSEDIVE_API_KEY"},
		"abusech":       {"ABUSECH_API_KEY"},
		"sophos_api":    {"SOPHOS_HOST", "SOPHOS_PORT", "SOPHOS_USER", "SOPHOS_PASSWORD"},
		"sophos_ssh":    {"SSH_HOST", "SSH_PORT", "SSH_USER", "SSH_KEY_PATH"},
		"sophos_syslog": {"SYSLOG_SOURCE_IP", "SYSLOG_PORT"},
	}

	for pluginID, envKeys := range envPlugins {
		// Skip if already in configs from file
		if _, exists := maskedConfigs[pluginID]; exists {
			continue
		}

		// Check if any env var is set
		pluginConfig := make(map[string]string)
		hasAnyValue := false
		for _, envKey := range envKeys {
			if value := os.Getenv(envKey); value != "" {
				hasAnyValue = true
				// Mask sensitive values using the same logic
				if shouldMaskField(envKey) {
					if len(value) > 4 {
						pluginConfig[envKey] = value[:4] + "****"
					} else {
						pluginConfig[envKey] = "****"
					}
				} else {
					pluginConfig[envKey] = value
				}
			}
		}

		if hasAnyValue {
			maskedConfigs[pluginID] = pluginConfig
		}
	}

	JSONResponse(w, http.StatusOK, maskedConfigs)
}

// ClearConfig removes a plugin configuration
// DELETE /api/v1/config/{plugin_id}
func (h *ConfigHandler) ClearConfig(w http.ResponseWriter, r *http.Request) {
	// Get plugin_id from URL path
	path := r.URL.Path
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(parts) < 1 {
		ErrorResponse(w, http.StatusBadRequest, "Plugin ID required", nil)
		return
	}
	pluginID := parts[len(parts)-1]

	if pluginID == "" {
		ErrorResponse(w, http.StatusBadRequest, "Plugin ID required", nil)
		return
	}

	// Remove from config file
	if err := h.clearIntegrationConfig(pluginID); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to clear configuration", err)
		return
	}

	// Clear environment variables
	h.clearConfigFromEnv(pluginID)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   fmt.Sprintf("Configuration for %s has been cleared", pluginID),
		"plugin_id": pluginID,
	})
}

// clearIntegrationConfig removes a plugin from the config file
func (h *ConfigHandler) clearIntegrationConfig(pluginID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Load existing configs
	configs := make(map[string]IntegrationConfig)
	if data, err := os.ReadFile(h.configPath); err == nil {
		json.Unmarshal(data, &configs)
	}

	// Delete the plugin config
	delete(configs, pluginID)

	// Save
	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(h.configPath, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// clearConfigFromEnv clears environment variables for a plugin
func (h *ConfigHandler) clearConfigFromEnv(pluginID string) {
	envKeys := map[string][]string{
		"sophos_api":         {"SOPHOS_HOST", "SOPHOS_PORT", "SOPHOS_USER", "SOPHOS_PASSWORD"},
		"sophos_ssh":         {"SSH_HOST", "SSH_PORT", "SSH_USER", "SSH_KEY_PATH"},
		"sophos_syslog":      {"SYSLOG_SOURCE_IP", "SYSLOG_PORT"},
		"abuseipdb":          {"ABUSEIPDB_API_KEY"},
		"virustotal":         {"VIRUSTOTAL_API_KEY"},
		"alienvault":         {"ALIENVAULT_API_KEY"},
		"greynoise":          {"GREYNOISE_API_KEY"},
		"crowdsec":           {"CROWDSEC_API_KEY"},
		"crowdsec_blocklist": {"CROWDSEC_BLOCKLIST_API_KEY"},
		"criminalip":         {"CRIMINALIP_API_KEY"},
		"pulsedive":          {"PULSEDIVE_API_KEY"},
		"smtp":               {"SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_FROM_EMAIL", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_RECIPIENTS"},
	}

	if keys, ok := envKeys[pluginID]; ok {
		for _, key := range keys {
			os.Unsetenv(key)
		}
	}
}

// testIntegration tests a specific integration
func (h *ConfigHandler) testIntegration(pluginID string, fields map[string]string) ConfigTestResponse {
	switch pluginID {
	case "sophos_api":
		return h.testSophosAPI(fields)
	case "sophos_ssh":
		return h.testSophosSSH(fields)
	case "abuseipdb", "virustotal", "alienvault", "greynoise", "crowdsec", "criminalip", "pulsedive":
		return h.testThreatIntelAPI(pluginID, fields)
	case "crowdsec_blocklist":
		return h.testCrowdSecBlocklist(fields)
	case "smtp":
		return h.testSMTP(fields)
	default:
		return ConfigTestResponse{
			Success: false,
			Message: "Unknown plugin",
			Status:  "invalid",
		}
	}
}

// testSophosAPI tests Sophos XGS API connection
func (h *ConfigHandler) testSophosAPI(fields map[string]string) ConfigTestResponse {
	host := fields["SOPHOS_HOST"]
	port := fields["SOPHOS_PORT"]
	if port == "" {
		port = "4444"
	}

	if host == "" {
		return ConfigTestResponse{
			Success: false,
			Message: "Host is required",
			Status:  "invalid",
		}
	}

	// Test TCP connection to Sophos API port
	address := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return ConfigTestResponse{
			Success: false,
			Message: fmt.Sprintf("Cannot connect to %s: %v", address, err),
			Status:  "failed",
		}
	}
	conn.Close()

	return ConfigTestResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully connected to Sophos API at %s", address),
		Status:  "connected",
	}
}

// testSophosSSH tests SSH connection to Sophos XGS
func (h *ConfigHandler) testSophosSSH(fields map[string]string) ConfigTestResponse {
	host := fields["SSH_HOST"]
	port := fields["SSH_PORT"]
	user := fields["SSH_USER"]
	keyPath := fields["SSH_KEY_PATH"]

	if port == "" {
		port = "22"
	}

	if host == "" || user == "" {
		return ConfigTestResponse{
			Success: false,
			Message: "Host and username are required",
			Status:  "invalid",
		}
	}

	// If key path provided, try to read it
	var authMethods []ssh.AuthMethod
	if keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return ConfigTestResponse{
				Success: false,
				Message: fmt.Sprintf("Cannot read SSH key: %v", err),
				Status:  "invalid",
			}
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return ConfigTestResponse{
				Success: false,
				Message: fmt.Sprintf("Invalid SSH key: %v", err),
				Status:  "invalid",
			}
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	address := fmt.Sprintf("%s:%s", host, port)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return ConfigTestResponse{
			Success: false,
			Message: fmt.Sprintf("SSH connection failed: %v", err),
			Status:  "failed",
		}
	}
	client.Close()

	return ConfigTestResponse{
		Success: true,
		Message: fmt.Sprintf("SSH connection successful to %s@%s", user, host),
		Status:  "connected",
	}
}

// testThreatIntelAPI tests threat intelligence API
func (h *ConfigHandler) testThreatIntelAPI(pluginID string, fields map[string]string) ConfigTestResponse {
	var apiKey string
	var apiName string

	switch pluginID {
	case "abuseipdb":
		apiKey = fields["ABUSEIPDB_API_KEY"]
		apiName = "AbuseIPDB"
	case "virustotal":
		apiKey = fields["VIRUSTOTAL_API_KEY"]
		apiName = "VirusTotal"
	case "alienvault":
		apiKey = fields["ALIENVAULT_API_KEY"]
		apiName = "AlienVault OTX"
	case "greynoise":
		apiKey = fields["GREYNOISE_API_KEY"]
		apiName = "GreyNoise"
	case "crowdsec":
		apiKey = fields["CROWDSEC_API_KEY"]
		apiName = "CrowdSec CTI"
	case "criminalip":
		apiKey = fields["CRIMINALIP_API_KEY"]
		apiName = "Criminal IP"
	case "pulsedive":
		apiKey = fields["PULSEDIVE_API_KEY"]
		apiName = "Pulsedive"
	}

	if apiKey == "" {
		return ConfigTestResponse{
			Success: false,
			Message: "API key is required",
			Status:  "invalid",
		}
	}

	// Basic validation - check key format/length
	if len(apiKey) < 10 {
		return ConfigTestResponse{
			Success: false,
			Message: "API key appears to be too short",
			Status:  "invalid",
		}
	}

	// For now, we just validate the format
	// A full test would make an API call which might use rate limits
	return ConfigTestResponse{
		Success: true,
		Message: fmt.Sprintf("%s API key configured (format valid)", apiName),
		Status:  "connected",
	}
}

// testSMTP tests SMTP server connection
func (h *ConfigHandler) testSMTP(fields map[string]string) ConfigTestResponse {
	host := fields["SMTP_HOST"]
	port := fields["SMTP_PORT"]
	security := fields["SMTP_SECURITY"]
	username := fields["SMTP_USERNAME"]
	password := fields["SMTP_PASSWORD"]

	if host == "" {
		return ConfigTestResponse{
			Success: false,
			Message: "SMTP host is required",
			Status:  "invalid",
		}
	}

	if port == "" {
		port = "587"
	}

	if security == "" {
		security = "tls"
	}

	// Test TCP connection first
	address := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return ConfigTestResponse{
			Success: false,
			Message: fmt.Sprintf("Cannot connect to SMTP server %s: %v", address, err),
			Status:  "failed",
		}
	}
	conn.Close()

	// If credentials provided, we could do a full auth test
	// For now, just verify connectivity
	if username != "" && password != "" {
		return ConfigTestResponse{
			Success: true,
			Message: fmt.Sprintf("SMTP server %s reachable (credentials configured)", address),
			Status:  "connected",
		}
	}

	return ConfigTestResponse{
		Success: true,
		Message: fmt.Sprintf("SMTP server %s reachable (no credentials configured)", address),
		Status:  "connected",
	}
}

// testCrowdSecBlocklist tests CrowdSec Blocklist API connection
func (h *ConfigHandler) testCrowdSecBlocklist(fields map[string]string) ConfigTestResponse {
	apiKey := fields["CROWDSEC_BLOCKLIST_API_KEY"]

	if apiKey == "" {
		return ConfigTestResponse{
			Success: false,
			Message: "Blocklist API key is required",
			Status:  "invalid",
		}
	}

	// Basic validation - CrowdSec Service API keys are 64 character hex strings
	if len(apiKey) < 32 {
		return ConfigTestResponse{
			Success: false,
			Message: "API key appears to be too short (expected 64 characters)",
			Status:  "invalid",
		}
	}

	// Test actual connection to CrowdSec API
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://admin.api.crowdsec.net/v1/blocklists?page_size=1", nil)
	if err != nil {
		return ConfigTestResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to create request: %v", err),
			Status:  "failed",
		}
	}

	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return ConfigTestResponse{
			Success: false,
			Message: fmt.Sprintf("Connection failed: %v", err),
			Status:  "failed",
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return ConfigTestResponse{
			Success: false,
			Message: "Invalid API key - check your CrowdSec Service API key",
			Status:  "failed",
		}
	}

	if resp.StatusCode == http.StatusForbidden {
		return ConfigTestResponse{
			Success: false,
			Message: "API key does not have Blocklist read permission",
			Status:  "failed",
		}
	}

	if resp.StatusCode != http.StatusOK {
		return ConfigTestResponse{
			Success: false,
			Message: fmt.Sprintf("API error (status %d)", resp.StatusCode),
			Status:  "failed",
		}
	}

	return ConfigTestResponse{
		Success: true,
		Message: "CrowdSec Blocklist API connected successfully",
		Status:  "connected",
	}
}

// saveIntegrationConfig saves config to file
func (h *ConfigHandler) saveIntegrationConfig(pluginID string, fields map[string]string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Ensure config directory exists
	configDir := filepath.Dir(h.configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Load existing configs
	configs := make(map[string]IntegrationConfig)
	if data, err := os.ReadFile(h.configPath); err == nil {
		json.Unmarshal(data, &configs)
	}

	// Merge new fields with existing (preserve fields not sent, like masked passwords)
	existingFields := make(map[string]string)
	if existing, ok := configs[pluginID]; ok {
		existingFields = existing.Fields
	}

	// Merge: new values override existing, but missing fields are preserved
	mergedFields := make(map[string]string)
	for k, v := range existingFields {
		mergedFields[k] = v
	}
	for k, v := range fields {
		if v != "" { // Only override if new value is not empty
			mergedFields[k] = v
		}
	}

	// Update config
	configs[pluginID] = IntegrationConfig{
		ID:        pluginID,
		Fields:    mergedFields,
		UpdatedAt: time.Now(),
	}

	// Save
	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(h.configPath, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// loadAllConfigs loads all saved configurations
func (h *ConfigHandler) loadAllConfigs() map[string]IntegrationConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()

	configs := make(map[string]IntegrationConfig)
	if data, err := os.ReadFile(h.configPath); err == nil {
		json.Unmarshal(data, &configs)
	}
	return configs
}

// getMergedConfig returns the merged config (existing + new fields)
func (h *ConfigHandler) getMergedConfig(pluginID string, newFields map[string]string) map[string]string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Load existing configs
	configs := make(map[string]IntegrationConfig)
	if data, err := os.ReadFile(h.configPath); err == nil {
		json.Unmarshal(data, &configs)
	}

	// Start with existing fields
	mergedFields := make(map[string]string)
	if existing, ok := configs[pluginID]; ok {
		for k, v := range existing.Fields {
			mergedFields[k] = v
		}
	}

	// Override with new non-empty fields
	for k, v := range newFields {
		if v != "" {
			mergedFields[k] = v
		}
	}

	return mergedFields
}

// applyConfigToEnv updates environment variables in memory
func (h *ConfigHandler) applyConfigToEnv(pluginID string, fields map[string]string) {
	for key, value := range fields {
		if value != "" {
			os.Setenv(key, value)
		}
	}
}

// GetSystemWhitelist returns the system whitelist of protected IPs (default + custom)
// GET /api/v1/config/system-whitelist
func (h *ConfigHandler) GetSystemWhitelist(w http.ResponseWriter, r *http.Request) {
	defaultEntries := entity.DefaultSystemWhitelist()

	// Get custom entries if repo is configured
	var customEntries []entity.CustomSystemWhitelistEntry
	if h.sysWhitelistRepo != nil {
		var err error
		customEntries, err = h.sysWhitelistRepo.List(r.Context())
		if err != nil {
			// Log error but continue with default entries only
			fmt.Printf("[WARN] Failed to fetch custom whitelist: %v\n", err)
		}
	}

	// Combine all entries for display
	type DisplayEntry struct {
		ID          string `json:"id,omitempty"`
		IP          string `json:"ip"`
		Name        string `json:"name"`
		Provider    string `json:"provider"`
		Category    string `json:"category"`
		Description string `json:"description"`
		IsCustom    bool   `json:"is_custom"`
	}

	var allEntries []DisplayEntry
	allIPs := make([]string, 0)

	// Add default entries
	for _, e := range defaultEntries {
		allEntries = append(allEntries, DisplayEntry{
			IP:          e.IP,
			Name:        e.Name,
			Provider:    e.Provider,
			Category:    e.Category,
			Description: e.Description,
			IsCustom:    false,
		})
		allIPs = append(allIPs, e.IP)
	}

	// Add custom entries
	for _, e := range customEntries {
		allEntries = append(allEntries, DisplayEntry{
			ID:          e.ID,
			IP:          e.IP,
			Name:        e.Name,
			Provider:    e.Provider,
			Category:    e.Category,
			Description: e.Description,
			IsCustom:    true,
		})
		allIPs = append(allIPs, e.IP)
	}

	// Group by category
	byCategory := make(map[string][]DisplayEntry)
	for _, entry := range allEntries {
		byCategory[entry.Category] = append(byCategory[entry.Category], entry)
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"entries":        allEntries,
		"by_category":    byCategory,
		"ips":            allIPs,
		"count":          len(allEntries),
		"default_count":  len(defaultEntries),
		"custom_count":   len(customEntries),
		"custom_entries": customEntries,
	})
}

// CheckSystemWhitelist checks if an IP is in the system whitelist
// GET /api/v1/config/system-whitelist/check/{ip}
func (h *ConfigHandler) CheckSystemWhitelist(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Path[len("/api/v1/config/system-whitelist/check/"):]

	if entry := entity.GetSystemWhitelistEntry(ip); entry != nil {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"is_protected": true,
			"entry":        entry,
			"message":      fmt.Sprintf("IP %s is a protected system IP (%s - %s)", ip, entry.Provider, entry.Name),
		})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"is_protected": false,
		"message":      fmt.Sprintf("IP %s is not in the system whitelist", ip),
	})
}

// CreateSystemWhitelistEntry creates a new custom system whitelist entry
// POST /api/v1/config/system-whitelist
func (h *ConfigHandler) CreateSystemWhitelistEntry(w http.ResponseWriter, r *http.Request) {
	if h.sysWhitelistRepo == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "System whitelist repository not configured", nil)
		return
	}

	var req entity.CreateSystemWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.IP == "" {
		ErrorResponse(w, http.StatusBadRequest, "IP address is required", nil)
		return
	}
	if req.Name == "" {
		ErrorResponse(w, http.StatusBadRequest, "Name is required", nil)
		return
	}
	if req.Category == "" {
		req.Category = "custom"
	}

	// Check if IP already exists in default whitelist
	if entity.IsSystemWhitelisted(req.IP) {
		ErrorResponse(w, http.StatusConflict, "IP already exists in default system whitelist", nil)
		return
	}

	// Check if IP already exists in custom whitelist
	existing, _ := h.sysWhitelistRepo.GetByIP(r.Context(), req.IP)
	if existing != nil {
		ErrorResponse(w, http.StatusConflict, "IP already exists in custom system whitelist", nil)
		return
	}

	// Get username from context (set by auth middleware)
	username := "admin"
	if user := r.Context().Value("user"); user != nil {
		if u, ok := user.(map[string]interface{}); ok {
			if name, ok := u["username"].(string); ok {
				username = name
			}
		}
	}

	entry := &entity.CustomSystemWhitelistEntry{
		IP:          req.IP,
		Name:        req.Name,
		Provider:    req.Provider,
		Category:    req.Category,
		Description: req.Description,
		CreatedBy:   username,
		IsCustom:    true,
	}

	if err := h.sysWhitelistRepo.Create(r.Context(), entry); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to create entry", err)
		return
	}

	JSONResponse(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "System whitelist entry created",
		"entry":   entry,
	})
}

// UpdateSystemWhitelistEntry updates an existing custom system whitelist entry
// PUT /api/v1/config/system-whitelist/{id}
func (h *ConfigHandler) UpdateSystemWhitelistEntry(w http.ResponseWriter, r *http.Request) {
	if h.sysWhitelistRepo == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "System whitelist repository not configured", nil)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		ErrorResponse(w, http.StatusBadRequest, "Entry ID is required", nil)
		return
	}

	var req entity.UpdateSystemWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Get existing entry by iterating through custom entries
	entries, err := h.sysWhitelistRepo.List(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to fetch entries", err)
		return
	}

	var existing *entity.CustomSystemWhitelistEntry
	for _, e := range entries {
		if e.ID == id {
			existing = &e
			break
		}
	}

	if existing == nil {
		ErrorResponse(w, http.StatusNotFound, "Entry not found", nil)
		return
	}

	// Update fields
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Provider != "" {
		existing.Provider = req.Provider
	}
	if req.Category != "" {
		existing.Category = req.Category
	}
	if req.Description != "" {
		existing.Description = req.Description
	}

	if err := h.sysWhitelistRepo.Update(r.Context(), existing); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to update entry", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "System whitelist entry updated",
		"entry":   existing,
	})
}

// DeleteSystemWhitelistEntry deletes a custom system whitelist entry
// DELETE /api/v1/config/system-whitelist/{id}
func (h *ConfigHandler) DeleteSystemWhitelistEntry(w http.ResponseWriter, r *http.Request) {
	if h.sysWhitelistRepo == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "System whitelist repository not configured", nil)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		ErrorResponse(w, http.StatusBadRequest, "Entry ID is required", nil)
		return
	}

	if err := h.sysWhitelistRepo.Delete(r.Context(), id); err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to delete entry", err)
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "System whitelist entry deleted",
	})
}
