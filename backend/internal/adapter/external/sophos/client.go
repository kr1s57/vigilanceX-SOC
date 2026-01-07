package sophos

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	TransactionID string         `xml:"transactionid,attr,omitempty"`
	Name          string         `xml:"Name"`
	IPFamily      string         `xml:"IPFamily,omitempty"`
	HostType      string         `xml:"HostType,omitempty"`
	IPAddress     string         `xml:"IPAddress,omitempty"`
	HostGroupList *HostGroupList `xml:"HostGroupList,omitempty"`
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
	TransactionID string `xml:"transactionid,attr"`
	Status        Status `xml:"Status"`
	Name          string `xml:"Name"`
	IPFamily      string `xml:"IPFamily"`
	HostType      string `xml:"HostType"`
	IPAddress     string `xml:"IPAddress"`
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

// sendRequest sends an XML request to Sophos API using URL query parameter
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

	// Build URL with reqxml parameter (Sophos expects this format)
	xmlPayload := xml.Header + string(xmlData)
	reqURL := fmt.Sprintf("%s?reqxml=%s", c.baseURL, url.QueryEscape(xmlPayload))

	// Create HTTP request
	httpReq, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

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

	// First, create the IP host object
	createReq := &APIRequest{
		Set: &Set{
			Operation: "add",
			IPHost: &IPHost{
				Name:      hostName,
				IPFamily:  "IPv4",
				HostType:  "IP",
				IPAddress: ip,
				HostGroupList: &HostGroupList{
					HostGroup: []string{c.groupName},
				},
			},
		},
	}

	resp, err := c.sendRequest(createReq)
	if err != nil {
		return fmt.Errorf("failed to add IP host: %w", err)
	}

	// Check for existing host (code 502 means already exists)
	if resp.Status != nil && resp.Status.Code != 200 && resp.Status.Code != 502 {
		return fmt.Errorf("API error: %s (code: %d)", resp.Status.Message, resp.Status.Code)
	}

	return nil
}

// RemoveIPFromBlocklist removes an IP address from the blocklist
func (c *Client) RemoveIPFromBlocklist(ip string) error {
	hostName := fmt.Sprintf("bannedIP_%s", ip)

	// Remove the IP host object
	removeReq := &APIRequest{
		Remove: &Remove{
			IPHost: &IPHostFilter{
				Name: hostName,
			},
		},
	}

	resp, err := c.sendRequest(removeReq)
	if err != nil {
		return fmt.Errorf("failed to remove IP host: %w", err)
	}

	// Check response (code 541 means not found, which is OK)
	if resp.Status != nil && resp.Status.Code != 200 && resp.Status.Code != 541 {
		return fmt.Errorf("API error: %s (code: %d)", resp.Status.Message, resp.Status.Code)
	}

	return nil
}

// GetBlocklistIPs retrieves all IPs in the blocklist group
func (c *Client) GetBlocklistIPs() ([]string, error) {
	// Get the blocklist group
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
	var ips []string
	for _, group := range resp.IPHostGroup {
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

	count := 0
	for _, group := range resp.IPHostGroup {
		count += len(group.HostList.Host)
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
