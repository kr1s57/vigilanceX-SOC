package entity

import "time"

// SystemWhitelistEntry represents a system-protected IP that should never be blocked
type SystemWhitelistEntry struct {
	IP          string `json:"ip"`
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	Category    string `json:"category"` // dns, cdn, cloud, monitoring, security
	Description string `json:"description"`
}

// CustomSystemWhitelistEntry represents a custom entry added by admin (v3.57.117)
type CustomSystemWhitelistEntry struct {
	ID          string    `json:"id"`
	IP          string    `json:"ip"`
	Name        string    `json:"name"`
	Provider    string    `json:"provider"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedBy   string    `json:"created_by"`
	IsCustom    bool      `json:"is_custom"` // Always true for custom entries
}

// CreateSystemWhitelistRequest for creating a new custom entry
type CreateSystemWhitelistRequest struct {
	IP          string `json:"ip"`
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// UpdateSystemWhitelistRequest for updating a custom entry
type UpdateSystemWhitelistRequest struct {
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// SystemWhitelistCategory constants
const (
	CategoryDNS        = "dns"
	CategoryCDN        = "cdn"
	CategoryCloud      = "cloud"
	CategoryMonitoring = "monitoring"
	CategorySecurity   = "security"
)

// DefaultSystemWhitelist returns the list of IPs that should NEVER be blocked
// These are critical infrastructure IPs (DNS, CDN, Cloud providers, etc.)
func DefaultSystemWhitelist() []SystemWhitelistEntry {
	return []SystemWhitelistEntry{
		// === DNS Providers ===
		// Cloudflare DNS
		{IP: "1.1.1.1", Name: "Cloudflare DNS Primary", Provider: "Cloudflare", Category: CategoryDNS, Description: "Cloudflare public DNS resolver"},
		{IP: "1.0.0.1", Name: "Cloudflare DNS Secondary", Provider: "Cloudflare", Category: CategoryDNS, Description: "Cloudflare public DNS resolver"},
		// Google DNS
		{IP: "8.8.8.8", Name: "Google DNS Primary", Provider: "Google", Category: CategoryDNS, Description: "Google public DNS resolver"},
		{IP: "8.8.4.4", Name: "Google DNS Secondary", Provider: "Google", Category: CategoryDNS, Description: "Google public DNS resolver"},
		// Quad9 DNS
		{IP: "9.9.9.9", Name: "Quad9 DNS Primary", Provider: "Quad9", Category: CategoryDNS, Description: "Quad9 secure DNS resolver"},
		{IP: "149.112.112.112", Name: "Quad9 DNS Secondary", Provider: "Quad9", Category: CategoryDNS, Description: "Quad9 secure DNS resolver"},
		// OpenDNS
		{IP: "208.67.222.222", Name: "OpenDNS Primary", Provider: "Cisco OpenDNS", Category: CategoryDNS, Description: "OpenDNS public resolver"},
		{IP: "208.67.220.220", Name: "OpenDNS Secondary", Provider: "Cisco OpenDNS", Category: CategoryDNS, Description: "OpenDNS public resolver"},

		// === CDN Providers (Anycast IPs) ===
		// Note: Most CDN IPs are dynamic, but some are well-known

		// === Cloud Provider Health Checks ===
		// AWS Health Checks (common ranges)
		{IP: "54.243.31.192", Name: "AWS Health Check", Provider: "AWS", Category: CategoryCloud, Description: "AWS Route53 health check"},
		// Google Cloud Health Checks
		{IP: "35.191.0.1", Name: "Google Cloud Health Check", Provider: "Google Cloud", Category: CategoryCloud, Description: "GCP health check probe"},
		{IP: "130.211.0.1", Name: "Google Cloud Load Balancer", Provider: "Google Cloud", Category: CategoryCloud, Description: "GCP load balancer health check"},

		// === Monitoring Services ===
		// UptimeRobot (common IPs)
		{IP: "216.144.250.150", Name: "UptimeRobot", Provider: "UptimeRobot", Category: CategoryMonitoring, Description: "Uptime monitoring service"},
		// Pingdom
		{IP: "76.72.167.154", Name: "Pingdom Probe", Provider: "Pingdom", Category: CategoryMonitoring, Description: "Pingdom monitoring probe"},

		// === Security Services ===
		// Let's Encrypt validation
		// Note: Let's Encrypt uses various IPs, but validation should be allowed

		// === NTP Servers ===
		{IP: "129.6.15.28", Name: "NIST NTP", Provider: "NIST", Category: CategoryMonitoring, Description: "NIST time server (time-a.nist.gov)"},
		{IP: "129.6.15.29", Name: "NIST NTP", Provider: "NIST", Category: CategoryMonitoring, Description: "NIST time server (time-b.nist.gov)"},
	}
}

// GetSystemWhitelistIPs returns just the IP addresses as a slice
func GetSystemWhitelistIPs() []string {
	entries := DefaultSystemWhitelist()
	ips := make([]string, len(entries))
	for i, entry := range entries {
		ips[i] = entry.IP
	}
	return ips
}

// IsSystemWhitelisted checks if an IP is in the system whitelist
func IsSystemWhitelisted(ip string) bool {
	for _, entry := range DefaultSystemWhitelist() {
		if entry.IP == ip {
			return true
		}
	}
	return false
}

// GetSystemWhitelistEntry returns the entry for an IP if it exists
func GetSystemWhitelistEntry(ip string) *SystemWhitelistEntry {
	for _, entry := range DefaultSystemWhitelist() {
		if entry.IP == ip {
			return &entry
		}
	}
	return nil
}
