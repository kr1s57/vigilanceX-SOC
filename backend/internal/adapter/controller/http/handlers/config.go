package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ConfigHandler handles configuration management
type ConfigHandler struct {
	configPath string
	mu         sync.RWMutex
}

// NewConfigHandler creates a new config handler
func NewConfigHandler() *ConfigHandler {
	return &ConfigHandler{
		configPath: "/app/config/integrations.json",
	}
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

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"saved":   true,
		"test":    testResult,
		"message": "Configuration saved. " + testResult.Message,
	})
}

// GetConfig retrieves saved configuration
// GET /api/v1/config/{plugin_id}
func (h *ConfigHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	// Return masked config (don't expose full API keys)
	configs := h.loadAllConfigs()
	maskedConfigs := make(map[string]map[string]string)

	for id, config := range configs {
		maskedConfigs[id] = make(map[string]string)
		for key, value := range config.Fields {
			if strings.Contains(strings.ToLower(key), "password") ||
				strings.Contains(strings.ToLower(key), "key") ||
				strings.Contains(strings.ToLower(key), "secret") {
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

	JSONResponse(w, http.StatusOK, maskedConfigs)
}

// testIntegration tests a specific integration
func (h *ConfigHandler) testIntegration(pluginID string, fields map[string]string) ConfigTestResponse {
	switch pluginID {
	case "sophos_api":
		return h.testSophosAPI(fields)
	case "sophos_ssh":
		return h.testSophosSSH(fields)
	case "abuseipdb", "virustotal", "alienvault", "greynoise", "criminalip", "pulsedive":
		return h.testThreatIntelAPI(pluginID, fields)
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

	// Update config
	configs[pluginID] = IntegrationConfig{
		ID:        pluginID,
		Fields:    fields,
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

// applyConfigToEnv updates environment variables in memory
func (h *ConfigHandler) applyConfigToEnv(pluginID string, fields map[string]string) {
	for key, value := range fields {
		if value != "" {
			os.Setenv(key, value)
		}
	}
}
