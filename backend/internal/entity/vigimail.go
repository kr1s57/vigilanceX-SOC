package entity

import "time"

// VigimailConfig represents the configuration for the Vigimail checker service
type VigimailConfig struct {
	Enabled            bool      `json:"enabled"`
	CheckIntervalHours int       `json:"check_interval_hours"` // 6, 12, 24, 48, 168
	HIBPAPIKey         string    `json:"hibp_api_key,omitempty"`
	LeakCheckAPIKey    string    `json:"leakcheck_api_key,omitempty"`
	LastCheck          time.Time `json:"last_check"`
}

// VigimailDomain represents a domain being monitored
type VigimailDomain struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	CreatedAt time.Time `json:"created_at"`
	// Enriched fields (not stored)
	EmailCount int             `json:"email_count,omitempty"`
	LeakCount  int             `json:"leak_count,omitempty"`
	DNSCheck   *DomainDNSCheck `json:"dns_check,omitempty"`
}

// VigimailEmail represents an email address being monitored
type VigimailEmail struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Domain    string    `json:"domain"`
	LastCheck time.Time `json:"last_check"`
	LeakCount int       `json:"leak_count"`
	Status    string    `json:"status"` // pending, clean, leaked
	CreatedAt time.Time `json:"created_at"`
}

// VigimailLeak represents a data breach found for an email
type VigimailLeak struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Source      string    `json:"source"` // hibp, leakcheck
	BreachName  string    `json:"breach_name"`
	BreachDate  *string   `json:"breach_date,omitempty"`
	DataClasses []string  `json:"data_classes"` // passwords, emails, usernames, phone_numbers
	IsVerified  bool      `json:"is_verified"`
	IsSensitive bool      `json:"is_sensitive"`
	Description string    `json:"description,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// DomainDNSCheck represents the DNS configuration check results for a domain
type DomainDNSCheck struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	CheckTime time.Time `json:"check_time"`

	// SPF (Sender Policy Framework)
	SPFExists bool     `json:"spf_exists"`
	SPFRecord string   `json:"spf_record"`
	SPFValid  bool     `json:"spf_valid"`
	SPFIssues []string `json:"spf_issues"`

	// DKIM (DomainKeys Identified Mail)
	DKIMExists    bool     `json:"dkim_exists"`
	DKIMSelectors []string `json:"dkim_selectors"`
	DKIMValid     bool     `json:"dkim_valid"`
	DKIMIssues    []string `json:"dkim_issues"`

	// DMARC (Domain-based Message Authentication, Reporting & Conformance)
	DMARCExists bool     `json:"dmarc_exists"`
	DMARCRecord string   `json:"dmarc_record"`
	DMARCPolicy string   `json:"dmarc_policy"` // none, quarantine, reject
	DMARCValid  bool     `json:"dmarc_valid"`
	DMARCIssues []string `json:"dmarc_issues"`

	// MX Records
	MXExists  bool     `json:"mx_exists"`
	MXRecords []string `json:"mx_records"`

	// Overall Assessment
	OverallScore  int    `json:"overall_score"`  // 0-100
	OverallStatus string `json:"overall_status"` // good, warning, critical
}

// VigimailCheckHistory represents a check execution record
type VigimailCheckHistory struct {
	ID             string    `json:"id"`
	CheckTime      time.Time `json:"check_time"`
	CheckType      string    `json:"check_type"` // email_leak, domain_dns, full
	EmailsChecked  int       `json:"emails_checked"`
	DomainsChecked int       `json:"domains_checked"`
	LeaksFound     int       `json:"leaks_found"`
	DNSIssuesFound int       `json:"dns_issues_found"`
	DurationMS     int       `json:"duration_ms"`
	Success        bool      `json:"success"`
	Error          string    `json:"error,omitempty"`
}

// VigimailStatus represents the service status with statistics
type VigimailStatus struct {
	Enabled             bool      `json:"enabled"`
	WorkerRunning       bool      `json:"worker_running"`
	LastCheck           time.Time `json:"last_check"`
	NextCheck           time.Time `json:"next_check"`
	TotalDomains        int       `json:"total_domains"`
	TotalEmails         int       `json:"total_emails"`
	TotalLeaks          int       `json:"total_leaks"`
	EmailsWithLeaks     int       `json:"emails_with_leaks"`
	DomainsAtRisk       int       `json:"domains_at_risk"` // DNS issues
	HIBPConfigured      bool      `json:"hibp_configured"`
	LeakCheckConfigured bool      `json:"leakcheck_configured"`
}

// VigimailStats represents aggregated statistics
type VigimailStats struct {
	TotalDomains    int            `json:"total_domains"`
	TotalEmails     int            `json:"total_emails"`
	TotalLeaks      int            `json:"total_leaks"`
	EmailsWithLeaks int            `json:"emails_with_leaks"`
	EmailsClean     int            `json:"emails_clean"`
	EmailsPending   int            `json:"emails_pending"`
	DomainsGood     int            `json:"domains_good"`
	DomainsWarning  int            `json:"domains_warning"`
	DomainsCritical int            `json:"domains_critical"`
	LeaksBySource   map[string]int `json:"leaks_by_source"`
	TopBreaches     []BreachStat   `json:"top_breaches"`
}

// BreachStat represents statistics for a specific breach
type BreachStat struct {
	Name          string `json:"name"`
	AffectedCount int    `json:"affected_count"`
	Date          string `json:"date,omitempty"`
}

// DefaultVigimailConfig returns the default configuration
func DefaultVigimailConfig() *VigimailConfig {
	return &VigimailConfig{
		Enabled:            false,
		CheckIntervalHours: 24,
		HIBPAPIKey:         "",
		LeakCheckAPIKey:    "",
		LastCheck:          time.Time{},
	}
}
