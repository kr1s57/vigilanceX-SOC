package sophos

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Client handles communication with Sophos XGS XML API
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
	groupName  string
}

// Config holds Sophos client configuration
type Config struct {
	Host       string
	Port       int
	Username   string
	Password   string
	GroupName  string
	SkipVerify bool
	Timeout    time.Duration
}

// NewClient creates a new Sophos API client
func NewClient(cfg Config) *Client {
	if cfg.Port == 0 {
		cfg.Port = 4444
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.GroupName == "" {
		cfg.GroupName = "VIGILANCE_X_BLOCKLIST"
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipVerify,
		},
	}

	return &Client{
		baseURL:   fmt.Sprintf("https://%s:%d/webconsole/APIController", cfg.Host, cfg.Port),
		username:  cfg.Username,
		password:  cfg.Password,
		groupName: cfg.GroupName,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
	}
}

// APIRequest represents the root XML request structure
type APIRequest struct {
	XMLName xml.Name `xml:"Request"`
	Login   Login    `xml:"Login"`
	Set     *Set     `xml:"Set,omitempty"`
	Get     *Get     `xml:"Get,omitempty"`
	Remove  *Remove  `xml:"Remove,omitempty"`
}

// Login contains authentication credentials
type Login struct {
	Username string `xml:"Username"`
	Password string `xml:"Password"`
}

// Set operation for creating/updating objects
type Set struct {
	Operation   string       `xml:"operation,attr,omitempty"`
	IPHost      *IPHost      `xml:"IPHost,omitempty"`
	IPHostGroup *IPHostGroup `xml:"IPHostGroup,omitempty"`
}

// Get operation for retrieving objects
type Get struct {
	IPHost      *IPHostFilter      `xml:"IPHost,omitempty"`
	IPHostGroup *IPHostGroupFilter `xml:"IPHostGroup,omitempty"`
}

// Remove operation for deleting objects
type Remove struct {
	IPHost *IPHostFilter `xml:"IPHost,omitempty"`
}

// IPHost represents an IP host object
type IPHost struct {
	TransactionID     string         `xml:"transactionid,attr,omitempty"`
	Name              string         `xml:"Name"`
	IPFamily          string         `xml:"IPFamily,omitempty"`
	HostType          string         `xml:"HostType,omitempty"`
	IPAddress         string         `xml:"IPAddress,omitempty"`
	ListOfIPAddresses string         `xml:"ListOfIPAddresses,omitempty"` // For IPList type (comma-separated IPs)
	HostGroupList     *HostGroupList `xml:"HostGroupList,omitempty"`
}

// IPHostGroup represents an IP host group
type IPHostGroup struct {
	TransactionID string    `xml:"transactionid,attr,omitempty"`
	Name          string    `xml:"Name"`
	Description   string    `xml:"Description,omitempty"`
	HostList      *HostList `xml:"HostList,omitempty"`
}

// HostGroupList contains a list of host groups
type HostGroupList struct {
	HostGroup []string `xml:"HostGroup"`
}

// HostList contains a list of hosts
type HostList struct {
	Host []string `xml:"Host"`
}

// IPHostFilter for querying IP hosts
type IPHostFilter struct {
	Name string `xml:"Name,omitempty"`
}

// IPHostGroupFilter for querying IP host groups
type IPHostGroupFilter struct {
	Name string `xml:"Name,omitempty"`
}

// APIResponse represents the root XML response structure
type APIResponse struct {
	XMLName     xml.Name              `xml:"Response"`
	Status      *Status               `xml:"Status,omitempty"`
	IPHost      []IPHostResponse      `xml:"IPHost,omitempty"`
	IPHostGroup []IPHostGroupResponse `xml:"IPHostGroup,omitempty"`
	Login       *LoginResponse        `xml:"Login,omitempty"`
}

// Status contains operation status
type Status struct {
	Code    int    `xml:"code,attr"`
	Message string `xml:",chardata"`
}

// IPHostResponse for IP host query results
type IPHostResponse struct {
	TransactionID     string `xml:"transactionid,attr"`
	Status            Status `xml:"Status"`
	Name              string `xml:"Name"`
	IPFamily          string `xml:"IPFamily"`
	HostType          string `xml:"HostType"`
	IPAddress         string `xml:"IPAddress"`
	ListOfIPAddresses string `xml:"ListOfIPAddresses"` // v3.57.111: For IPList type hosts
}

// IPHostGroupResponse for IP host group query results
type IPHostGroupResponse struct {
	TransactionID string   `xml:"transactionid,attr"`
	Status        Status   `xml:"Status"`
	Name          string   `xml:"Name"`
	Description   string   `xml:"Description"`
	HostList      HostList `xml:"HostList"`
}

// LoginResponse contains login result
type LoginResponse struct {
	Status string `xml:"status,attr"`
}

// sendRequest sends an XML request to Sophos API using POST body
// Uses POST with form-encoded body to support large payloads (e.g., IPList with 1000+ IPs)
func (c *Client) sendRequest(req *APIRequest) (*APIResponse, error) {
	// Set login credentials
	req.Login = Login{
		Username: c.username,
		Password: c.password,
	}

	// Marshal request to XML
	xmlData, err := xml.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build XML payload with header
	xmlPayload := xml.Header + string(xmlData)

	// Use POST with form-encoded body (supports large payloads unlike URL query params)
	formData := url.Values{}
	formData.Set("reqxml", xmlPayload)

	// Create HTTP POST request with body
	httpReq, err := http.NewRequest("POST", c.baseURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for empty response
	if len(body) == 0 {
		return nil, fmt.Errorf("empty response from API")
	}

	// Parse response
	var apiResp APIResponse
	if err := xml.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &apiResp, nil
}

// AddIPToBlocklist adds an IP address to the blocklist group
func (c *Client) AddIPToBlocklist(ip, reason string) error {
	// Create host name from IP (format: bannedIP_x.x.x.x to match existing convention)
	hostName := fmt.Sprintf("bannedIP_%s", ip)

	// Step 1: Create the IP host object (without group assignment)
	createReq := &APIRequest{
		Set: &Set{
			Operation: "add",
			IPHost: &IPHost{
				Name:      hostName,
				IPFamily:  "IPv4",
				HostType:  "IP",
				IPAddress: ip,
			},
		},
	}

	resp, err := c.sendRequest(createReq)
	if err != nil {
		return fmt.Errorf("failed to add IP host: %w", err)
	}

	// Check for errors (502 = already exists, which is OK)
	if resp.Status != nil && resp.Status.Code != 200 && resp.Status.Code != 502 {
		return fmt.Errorf("API error creating host: %s (code: %d)", resp.Status.Message, resp.Status.Code)
	}

	// Step 2: Get current group members
	getReq := &APIRequest{
		Get: &Get{
			IPHostGroup: &IPHostGroupFilter{
				Name: c.groupName,
			},
		},
	}

	resp, err = c.sendRequest(getReq)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	// Find our group and get current hosts
	var currentHosts []string
	for _, group := range resp.IPHostGroup {
		if group.Name == c.groupName {
			currentHosts = group.HostList.Host
			break
		}
	}

	// Check if host is already in group
	for _, h := range currentHosts {
		if h == hostName {
			return nil // Already in group, nothing to do
		}
	}

	// Step 3: Update group to add the new host
	newHosts := append(currentHosts, hostName)
	updateReq := &APIRequest{
		Set: &Set{
			Operation: "update",
			IPHostGroup: &IPHostGroup{
				Name: c.groupName,
				HostList: &HostList{
					Host: newHosts,
				},
			},
		},
	}

	resp, err = c.sendRequest(updateReq)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}

	if resp.Status != nil && resp.Status.Code != 200 {
		return fmt.Errorf("API error updating group: %s (code: %d)", resp.Status.Message, resp.Status.Code)
	}

	return nil
}

// RemoveIPFromBlocklist removes an IP address from the blocklist
func (c *Client) RemoveIPFromBlocklist(ip string) error {
	hostName := fmt.Sprintf("bannedIP_%s", ip)

	// Step 1: Get current group members
	getReq := &APIRequest{
		Get: &Get{
			IPHostGroup: &IPHostGroupFilter{
				Name: c.groupName,
			},
		},
	}

	resp, err := c.sendRequest(getReq)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	// Find our group and get current hosts
	var currentHosts []string
	for _, group := range resp.IPHostGroup {
		if group.Name == c.groupName {
			currentHosts = group.HostList.Host
			break
		}
	}

	// Step 2: Remove host from list
	var newHosts []string
	found := false
	for _, h := range currentHosts {
		if h == hostName {
			found = true
			continue // Skip this host
		}
		newHosts = append(newHosts, h)
	}

	// If host wasn't in group, nothing to do
	if !found {
		return nil
	}

	// Step 3: Update group with new host list
	updateReq := &APIRequest{
		Set: &Set{
			Operation: "update",
			IPHostGroup: &IPHostGroup{
				Name: c.groupName,
				HostList: &HostList{
					Host: newHosts,
				},
			},
		},
	}

	resp, err = c.sendRequest(updateReq)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}

	if resp.Status != nil && resp.Status.Code != 200 {
		return fmt.Errorf("API error updating group: %s (code: %d)", resp.Status.Message, resp.Status.Code)
	}

	// Step 4: Delete the IP host object (cleanup)
	removeReq := &APIRequest{
		Remove: &Remove{
			IPHost: &IPHostFilter{
				Name: hostName,
			},
		},
	}

	resp, err = c.sendRequest(removeReq)
	if err != nil {
		// Not critical if host deletion fails
		return nil
	}

	return nil
}

// GetBlocklistIPs retrieves all IPs in the blocklist group
func (c *Client) GetBlocklistIPs() ([]string, error) {
	// Get the blocklist group
	// Note: Sophos API returns ALL groups when using Name filter, so we must filter in code
	getReq := &APIRequest{
		Get: &Get{
			IPHostGroup: &IPHostGroupFilter{
				Name: c.groupName,
			},
		},
	}

	resp, err := c.sendRequest(getReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocklist group: %w", err)
	}

	// Extract IPs from host names (format: bannedIP_x.x.x.x)
	// IMPORTANT: Filter by group name since Sophos API returns all groups
	var ips []string
	for _, group := range resp.IPHostGroup {
		// Only process our specific blocklist group
		if group.Name != c.groupName {
			continue
		}
		for _, hostName := range group.HostList.Host {
			if strings.HasPrefix(hostName, "bannedIP_") {
				// Extract IP from host name
				ip := strings.TrimPrefix(hostName, "bannedIP_")
				ips = append(ips, ip)
			}
		}
	}

	return ips, nil
}

// GetBlocklistCount returns the count of IPs in the blocklist group (fast)
func (c *Client) GetBlocklistCount() (int, error) {
	getReq := &APIRequest{
		Get: &Get{
			IPHostGroup: &IPHostGroupFilter{
				Name: c.groupName,
			},
		},
	}

	resp, err := c.sendRequest(getReq)
	if err != nil {
		return 0, fmt.Errorf("failed to get blocklist group: %w", err)
	}

	// IMPORTANT: Filter by group name since Sophos API returns all groups
	count := 0
	for _, group := range resp.IPHostGroup {
		if group.Name == c.groupName {
			count = len(group.HostList.Host)
			break
		}
	}

	return count, nil
}

// EnsureBlocklistGroupExists creates the blocklist group if it doesn't exist
func (c *Client) EnsureBlocklistGroupExists() error {
	createReq := &APIRequest{
		Set: &Set{
			Operation: "add",
			IPHostGroup: &IPHostGroup{
				Name:        c.groupName,
				Description: "VIGILANCE X Auto-Blocklist - Managed by SOC automation",
			},
		},
	}

	resp, err := c.sendRequest(createReq)
	if err != nil {
		return fmt.Errorf("failed to create blocklist group: %w", err)
	}

	// Code 502 means already exists, which is OK
	if resp.Status != nil && resp.Status.Code != 200 && resp.Status.Code != 502 {
		return fmt.Errorf("API error: %s (code: %d)", resp.Status.Message, resp.Status.Code)
	}

	return nil
}

// TestConnection tests the connection to Sophos XGS
func (c *Client) TestConnection() error {
	// Try to get the blocklist group as a connection test
	getReq := &APIRequest{
		Get: &Get{
			IPHostGroup: &IPHostGroupFilter{
				Name: c.groupName,
			},
		},
	}

	_, err := c.sendRequest(getReq)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}

	return nil
}

// SyncStatus represents the sync state between VIGILANCE X and Sophos XGS
type SyncStatus struct {
	Connected     bool   `json:"connected"`
	GroupExists   bool   `json:"group_exists"`
	TotalInGroup  int    `json:"total_in_group"`
	LastSyncError string `json:"last_sync_error,omitempty"`
	Host          string `json:"host,omitempty"`
}

// GetSyncStatus returns the current sync status with Sophos XGS
func (c *Client) GetSyncStatus() (*SyncStatus, error) {
	status := &SyncStatus{
		Host: c.baseURL,
	}

	// Get blocklist count (also serves as connection test)
	count, err := c.GetBlocklistCount()
	if err != nil {
		status.LastSyncError = err.Error()
		return status, nil
	}

	status.Connected = true
	status.GroupExists = true
	status.TotalInGroup = count

	return status, nil
}

// ========== Methods with custom group name (for CrowdSec integration) ==========

// EnsureGroupExists creates a group if it doesn't exist (custom group name)
func (c *Client) EnsureGroupExists(groupName, description string) error {
	createReq := &APIRequest{
		Set: &Set{
			Operation: "add",
			IPHostGroup: &IPHostGroup{
				Name:        groupName,
				Description: description,
			},
		},
	}

	resp, err := c.sendRequest(createReq)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}

	// Code 502 means already exists, which is OK
	if resp.Status != nil && resp.Status.Code != 200 && resp.Status.Code != 502 {
		return fmt.Errorf("API error: %s (code: %d)", resp.Status.Message, resp.Status.Code)
	}

	return nil
}

// GetGroupIPs retrieves all IPs in a specific group
func (c *Client) GetGroupIPs(groupName string) ([]string, error) {
	getReq := &APIRequest{
		Get: &Get{
			IPHostGroup: &IPHostGroupFilter{
				Name: groupName,
			},
		},
	}

	resp, err := c.sendRequest(getReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	slog.Info("[XGS] GetGroupIPs response",
		"requested_group", groupName,
		"groups_in_response", len(resp.IPHostGroup))

	var ips []string
	for _, group := range resp.IPHostGroup {
		slog.Info("[XGS] Processing group",
			"group_name", group.Name,
			"hosts_count", len(group.HostList.Host))

		if group.Name != groupName {
			continue
		}
		for _, hostName := range group.HostList.Host {
			// Extract IP from various naming conventions
			if strings.HasPrefix(hostName, "bannedIP_") {
				ips = append(ips, strings.TrimPrefix(hostName, "bannedIP_"))
			} else if strings.HasPrefix(hostName, "crowdsec_") {
				ips = append(ips, strings.TrimPrefix(hostName, "crowdsec_"))
			} else if strings.HasPrefix(hostName, "CS_") {
				// CrowdSec Blocklist hosts use CS_ prefix
				ips = append(ips, strings.TrimPrefix(hostName, "CS_"))
			} else {
				// Fallback: return as-is
				ips = append(ips, hostName)
			}
		}
	}

	slog.Info("[XGS] GetGroupIPs result",
		"group", groupName,
		"total_ips", len(ips))

	return ips, nil
}

// AddIPToGroup adds an IP to a specific group with custom host prefix
func (c *Client) AddIPToGroup(ip, groupName, hostPrefix string) error {
	hostName := fmt.Sprintf("%s_%s", hostPrefix, ip)

	// Step 1: Create the IP host object
	createReq := &APIRequest{
		Set: &Set{
			Operation: "add",
			IPHost: &IPHost{
				Name:      hostName,
				IPFamily:  "IPv4",
				HostType:  "IP",
				IPAddress: ip,
			},
		},
	}

	resp, err := c.sendRequest(createReq)
	if err != nil {
		return fmt.Errorf("failed to add IP host: %w", err)
	}

	// Check for errors (502 = already exists, which is OK)
	if resp.Status != nil && resp.Status.Code != 200 && resp.Status.Code != 502 {
		return fmt.Errorf("API error creating host: %s (code: %d)", resp.Status.Message, resp.Status.Code)
	}

	// Step 2: Get current group members
	getReq := &APIRequest{
		Get: &Get{
			IPHostGroup: &IPHostGroupFilter{
				Name: groupName,
			},
		},
	}

	resp, err = c.sendRequest(getReq)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	// Find our group and get current hosts
	var currentHosts []string
	for _, group := range resp.IPHostGroup {
		if group.Name == groupName {
			currentHosts = group.HostList.Host
			break
		}
	}

	// Check if host is already in group
	for _, h := range currentHosts {
		if h == hostName {
			return nil // Already in group
		}
	}

	// Step 3: Update group to add the new host
	newHosts := append(currentHosts, hostName)
	updateReq := &APIRequest{
		Set: &Set{
			Operation: "update",
			IPHostGroup: &IPHostGroup{
				Name: groupName,
				HostList: &HostList{
					Host: newHosts,
				},
			},
		},
	}

	resp, err = c.sendRequest(updateReq)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}

	if resp.Status != nil && resp.Status.Code != 200 {
		return fmt.Errorf("API error updating group: %s (code: %d)", resp.Status.Message, resp.Status.Code)
	}

	return nil
}

// RemoveIPFromGroup removes an IP from a specific group
func (c *Client) RemoveIPFromGroup(ip, groupName, hostPrefix string) error {
	hostName := fmt.Sprintf("%s_%s", hostPrefix, ip)

	// Step 1: Get current group members
	getReq := &APIRequest{
		Get: &Get{
			IPHostGroup: &IPHostGroupFilter{
				Name: groupName,
			},
		},
	}

	resp, err := c.sendRequest(getReq)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	// Find our group and get current hosts
	var currentHosts []string
	for _, group := range resp.IPHostGroup {
		if group.Name == groupName {
			currentHosts = group.HostList.Host
			break
		}
	}

	// Step 2: Remove host from list
	var newHosts []string
	found := false
	for _, h := range currentHosts {
		if h == hostName {
			found = true
			continue
		}
		newHosts = append(newHosts, h)
	}

	if !found {
		return nil // Not in group
	}

	// Step 3: Update group with new host list
	updateReq := &APIRequest{
		Set: &Set{
			Operation: "update",
			IPHostGroup: &IPHostGroup{
				Name: groupName,
				HostList: &HostList{
					Host: newHosts,
				},
			},
		},
	}

	resp, err = c.sendRequest(updateReq)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}

	if resp.Status != nil && resp.Status.Code != 200 {
		return fmt.Errorf("API error updating group: %s (code: %d)", resp.Status.Message, resp.Status.Code)
	}

	// Step 4: Delete the IP host object (cleanup)
	removeReq := &APIRequest{
		Remove: &Remove{
			IPHost: &IPHostFilter{
				Name: hostName,
			},
		},
	}

	c.sendRequest(removeReq) // Ignore errors on cleanup

	return nil
}

// CreateIPListObject creates an IPHost object of type "IPList" containing multiple IPs
// This is much more efficient than creating individual host objects
// Uses the Sophos XGS IPList format with ListOfIPAddresses field
func (c *Client) CreateIPListObject(name string, ips []string) error {
	// Join IPs with commas for the IPList type
	ipList := strings.Join(ips, ",")

	createReq := &APIRequest{
		Set: &Set{
			Operation: "add",
			IPHost: &IPHost{
				Name:              name,
				IPFamily:          "IPv4",
				HostType:          "IPList",
				ListOfIPAddresses: ipList,
			},
		},
	}

	resp, err := c.sendRequest(createReq)
	if err != nil {
		return fmt.Errorf("failed to create IP list object: %w", err)
	}

	// Check for errors - Status is inside IPHost response, not at root level
	// 502 = already exists, which is OK for update scenarios
	if len(resp.IPHost) > 0 {
		status := resp.IPHost[0].Status
		if status.Code != 200 && status.Code != 502 {
			return fmt.Errorf("API error creating IP list: %s (code: %d)", status.Message, status.Code)
		}
	}

	slog.Info("[XGS] Created IPList object", "name", name, "ip_count", len(ips))
	return nil
}

// UpdateIPListObject updates an existing IPHost IPList object with new IPs
func (c *Client) UpdateIPListObject(name string, ips []string) error {
	// Join IPs with commas for the IPList type
	ipList := strings.Join(ips, ",")

	updateReq := &APIRequest{
		Set: &Set{
			Operation: "update",
			IPHost: &IPHost{
				Name:              name,
				IPFamily:          "IPv4",
				HostType:          "IPList",
				ListOfIPAddresses: ipList,
			},
		},
	}

	resp, err := c.sendRequest(updateReq)
	if err != nil {
		return fmt.Errorf("failed to update IP list object: %w", err)
	}

	// Check for errors - Status is inside IPHost response, not at root level
	if len(resp.IPHost) > 0 {
		status := resp.IPHost[0].Status
		if status.Code != 200 {
			return fmt.Errorf("API error updating IP list: %s (code: %d)", status.Message, status.Code)
		}
	}

	slog.Info("[XGS] Updated IPList object", "name", name, "ip_count", len(ips))
	return nil
}

// SyncGroupIPsWithList synchronizes using IP List objects (efficient for large lists)
// Creates/updates IP List objects that can be referenced directly in firewall rules
// Note: IPList objects cannot be added to IPHostGroups in Sophos XGS
// chunkSize determines how many IPs per List object (recommended: 1000-5000)
func (c *Client) SyncGroupIPsWithList(groupName, listPrefix string, targetIPs []string, chunkSize int) (int, error) {
	if chunkSize <= 0 {
		chunkSize = 1000 // Default chunk size
	}

	slog.Info("[XGS] Starting bulk IP sync with List objects",
		"group", groupName,
		"total_ips", len(targetIPs),
		"chunk_size", chunkSize)

	// Split IPs into chunks
	var chunks [][]string
	for i := 0; i < len(targetIPs); i += chunkSize {
		end := i + chunkSize
		if end > len(targetIPs) {
			end = len(targetIPs)
		}
		chunks = append(chunks, targetIPs[i:end])
	}

	slog.Info("[XGS] Split into chunks", "chunk_count", len(chunks))

	// Create/update IP List objects for each chunk
	var listNames []string
	successCount := 0
	for i, chunk := range chunks {
		listName := fmt.Sprintf("%s_List_%d", listPrefix, i+1)
		listNames = append(listNames, listName)

		// Try to update first, if fails try to create
		err := c.UpdateIPListObject(listName, chunk)
		if err != nil {
			// Try create instead
			err = c.CreateIPListObject(listName, chunk)
			if err != nil {
				slog.Error("[XGS] Failed to create IP list object",
					"name", listName,
					"error", err)
				continue
			}
		}
		successCount++
		slog.Info("[XGS] Created/updated IP list object",
			"name", listName,
			"ip_count", len(chunk))
	}

	// Note: IPList objects cannot be members of IPHostGroup in Sophos XGS
	// The created objects (CS_List_1, CS_List_2, etc.) should be referenced
	// directly in firewall rules for blocking
	slog.Info("[XGS] Bulk IP sync completed - IPList objects created",
		"list_prefix", listPrefix,
		"total_ips", len(targetIPs),
		"list_objects_created", successCount,
		"list_names", listNames,
		"note", "Add these IPList objects to your firewall rules for blocking")

	return len(targetIPs), nil
}

// SyncBlocklistIPLists synchronizes a CrowdSec blocklist to XGS IPList objects
// Creates/updates IPList objects with naming: grp_CS_{BlocklistName}_01, _02, etc.
// Each IPList contains max 1000 IPs (XGS limit)
// Returns: (total IPs synced, lists created/updated, error)
func (c *Client) SyncBlocklistIPLists(blocklistName string, ips []string) (int, int, error) {
	const maxIPsPerList = 1000

	if len(ips) == 0 {
		slog.Info("[XGS] No IPs to sync for blocklist", "blocklist", blocklistName)
		return 0, 0, nil
	}

	// Sanitize blocklist name for XGS object naming
	safeName := sanitizeBlocklistName(blocklistName)
	prefix := fmt.Sprintf("grp_CS_%s", safeName)

	slog.Info("[XGS] Syncing blocklist to IPLists",
		"blocklist", blocklistName,
		"safe_name", safeName,
		"prefix", prefix,
		"total_ips", len(ips))

	// Calculate number of lists needed
	numLists := (len(ips) + maxIPsPerList - 1) / maxIPsPerList

	// Create/update IPList objects for each chunk
	successCount := 0
	for i := 0; i < numLists; i++ {
		start := i * maxIPsPerList
		end := start + maxIPsPerList
		if end > len(ips) {
			end = len(ips)
		}
		chunk := ips[start:end]

		// List name: grp_CS_BotnetActors_01, grp_CS_BotnetActors_02, etc.
		listName := fmt.Sprintf("%s_%02d", prefix, i+1)

		// Try to update first, if fails try to create
		err := c.UpdateIPListObject(listName, chunk)
		if err != nil {
			// Try create instead
			err = c.CreateIPListObject(listName, chunk)
			if err != nil {
				slog.Error("[XGS] Failed to create/update IPList",
					"name", listName,
					"error", err)
				continue
			}
		}
		successCount++
		slog.Info("[XGS] Created/updated IPList",
			"name", listName,
			"ip_count", len(chunk),
			"chunk", fmt.Sprintf("%d/%d", i+1, numLists))
	}

	// Clean up old lists that are no longer needed
	// e.g., if we now have 5 lists but previously had 8, delete _06, _07, _08
	c.cleanupOldIPLists(prefix, numLists)

	slog.Info("[XGS] Blocklist sync completed",
		"blocklist", blocklistName,
		"total_ips", len(ips),
		"lists_synced", successCount)

	return len(ips), successCount, nil
}

// sanitizeBlocklistName converts blocklist label to safe XGS object name
func sanitizeBlocklistName(label string) string {
	// Map known blocklist labels to short names
	nameMap := map[string]string{
		"Curated Botnet Actors":    "BotnetActors",
		"Public Internet Scanners": "InternetScanners",
		"Malicious IPs":            "MaliciousIPs",
		"Tor Exit Nodes":           "TorExitNodes",
		"Known Attackers":          "KnownAttackers",
	}

	if safeName, ok := nameMap[label]; ok {
		return safeName
	}

	// Generic sanitization: remove spaces and special chars
	safe := ""
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			safe += string(r)
		}
	}
	if len(safe) > 20 {
		safe = safe[:20]
	}
	return safe
}

// cleanupOldIPLists removes IPList objects that are no longer needed
// e.g., if blocklist shrunk from 8 lists to 5, delete _06, _07, _08
func (c *Client) cleanupOldIPLists(prefix string, currentCount int) {
	// Try to delete lists starting from currentCount+1 up to a reasonable max (50)
	for i := currentCount + 1; i <= 50; i++ {
		listName := fmt.Sprintf("%s_%02d", prefix, i)
		err := c.DeleteIPHost(listName)
		if err != nil {
			// Object doesn't exist or can't be deleted, stop trying
			break
		}
		slog.Info("[XGS] Deleted old IPList", "name", listName)
	}
}

// DeleteIPHost removes an IPHost object from XGS
func (c *Client) DeleteIPHost(name string) error {
	deleteReq := &APIRequest{
		Remove: &Remove{
			IPHost: &IPHostFilter{
				Name: name,
			},
		},
	}

	resp, err := c.sendRequest(deleteReq)
	if err != nil {
		return fmt.Errorf("failed to delete IPHost: %w", err)
	}

	// Check for errors
	if len(resp.IPHost) > 0 {
		status := resp.IPHost[0].Status
		if status.Code != 200 && status.Code != 0 {
			return fmt.Errorf("API error deleting IPHost: %s (code: %d)", status.Message, status.Code)
		}
	}

	return nil
}

// GetBlocklistIPLists returns all IPList names for a blocklist
func (c *Client) GetBlocklistIPLists(blocklistName string) ([]string, error) {
	safeName := sanitizeBlocklistName(blocklistName)
	prefix := fmt.Sprintf("grp_CS_%s", safeName)

	var lists []string
	for i := 1; i <= 50; i++ {
		listName := fmt.Sprintf("%s_%02d", prefix, i)
		// Try to get the IPHost - if it exists, add to list
		getReq := &APIRequest{
			Get: &Get{
				IPHost: &IPHostFilter{
					Name: listName,
				},
			},
		}

		resp, err := c.sendRequest(getReq)
		if err != nil {
			break
		}

		// Check if we got a valid response
		found := false
		for _, host := range resp.IPHost {
			if host.Name == listName {
				lists = append(lists, listName)
				found = true
				break
			}
		}
		if !found {
			break // No more lists
		}
	}

	return lists, nil
}

// GetAllCrowdSecGroups returns all grp_CS_* IPHost groups with their IP counts
// v3.57.111: Added to display per-blocklist XGS groups
// Returns slice of maps with "name" and "ip_count" keys for interface compatibility
func (c *Client) GetAllCrowdSecGroups() ([]map[string]interface{}, error) {
	// Get all IPHosts that start with grp_CS_
	getReq := &APIRequest{
		Get: &Get{
			IPHost: &IPHostFilter{
				// Empty filter to get all
			},
		},
	}

	resp, err := c.sendRequest(getReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP hosts: %w", err)
	}

	var groups []map[string]interface{}
	for _, host := range resp.IPHost {
		// Only include grp_CS_* groups
		if strings.HasPrefix(host.Name, "grp_CS_") {
			ipCount := 0
			// Count IPs in the ListOfIPAddresses field
			if host.ListOfIPAddresses != "" {
				// IPs are comma-separated
				ips := strings.Split(host.ListOfIPAddresses, ",")
				for _, ip := range ips {
					if strings.TrimSpace(ip) != "" {
						ipCount++
					}
				}
			}
			groups = append(groups, map[string]interface{}{
				"name":     host.Name,
				"ip_count": ipCount,
			})
		}
	}

	// Sort by name for consistent display
	sort.Slice(groups, func(i, j int) bool {
		return groups[i]["name"].(string) < groups[j]["name"].(string)
	})

	slog.Info("[XGS] GetAllCrowdSecGroups result",
		"count", len(groups))

	return groups, nil
}

// SyncGroupIPs synchronizes a group to contain exactly the given IPs
// Returns: (added count, removed count, error)
// NOTE: For large lists (>100 IPs), consider using SyncGroupIPsWithList instead
func (c *Client) SyncGroupIPs(groupName, hostPrefix string, targetIPs []string) (int, int, error) {
	// For large lists, use the efficient List-based method
	if len(targetIPs) > 100 {
		slog.Info("[XGS] Large IP list detected, using bulk sync method",
			"count", len(targetIPs))
		added, err := c.SyncGroupIPsWithList(groupName, hostPrefix, targetIPs, 1000)
		return added, 0, err
	}

	// Get current IPs in group
	currentIPs, err := c.GetGroupIPs(groupName)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get current IPs: %w", err)
	}

	// Build sets for comparison
	currentSet := make(map[string]bool)
	for _, ip := range currentIPs {
		currentSet[ip] = true
	}

	targetSet := make(map[string]bool)
	for _, ip := range targetIPs {
		targetSet[ip] = true
	}

	// Find IPs to add
	var toAdd []string
	for _, ip := range targetIPs {
		if !currentSet[ip] {
			toAdd = append(toAdd, ip)
		}
	}

	// Find IPs to remove
	var toRemove []string
	for _, ip := range currentIPs {
		if !targetSet[ip] {
			toRemove = append(toRemove, ip)
		}
	}

	// Perform adds
	added := 0
	for _, ip := range toAdd {
		if err := c.AddIPToGroup(ip, groupName, hostPrefix); err != nil {
			// Log but continue
			continue
		}
		added++
	}

	// Perform removes
	removed := 0
	for _, ip := range toRemove {
		if err := c.RemoveIPFromGroup(ip, groupName, hostPrefix); err != nil {
			// Log but continue
			continue
		}
		removed++
	}

	return added, removed, nil
}
