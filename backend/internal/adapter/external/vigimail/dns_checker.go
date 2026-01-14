package vigimail

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// Common DKIM selectors to check
var commonDKIMSelectors = []string{
	"default",
	"google",
	"selector1", // Microsoft
	"selector2", // Microsoft
	"k1",        // Mailchimp
	"s1",
	"s2",
	"dkim",
	"mail",
	"email",
}

// DNSChecker performs DNS checks for email security configurations
type DNSChecker struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// NewDNSChecker creates a new DNS checker
func NewDNSChecker() *DNSChecker {
	return &DNSChecker{
		resolver: net.DefaultResolver,
		timeout:  10 * time.Second,
	}
}

// CheckDomain performs a full DNS check for a domain
func (c *DNSChecker) CheckDomain(ctx context.Context, domain string) (*entity.DomainDNSCheck, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	check := &entity.DomainDNSCheck{
		Domain:    domain,
		CheckTime: time.Now(),
	}

	// Check MX records first (proves it's an email domain)
	c.checkMX(ctx, domain, check)

	// Check SPF
	c.checkSPF(ctx, domain, check)

	// Check DKIM
	c.checkDKIM(ctx, domain, check)

	// Check DMARC
	c.checkDMARC(ctx, domain, check)

	// Calculate overall score and status
	c.calculateOverall(check)

	slog.Info("[DNS_CHECK] Completed", "domain", domain, "score", check.OverallScore, "status", check.OverallStatus)
	return check, nil
}

// checkMX checks for MX records
func (c *DNSChecker) checkMX(ctx context.Context, domain string, check *entity.DomainDNSCheck) {
	records, err := c.resolver.LookupMX(ctx, domain)
	if err != nil {
		slog.Debug("[DNS_CHECK] MX lookup failed", "domain", domain, "error", err)
		return
	}

	if len(records) > 0 {
		check.MXExists = true
		for _, mx := range records {
			check.MXRecords = append(check.MXRecords, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
	}
}

// checkSPF checks for SPF record
func (c *DNSChecker) checkSPF(ctx context.Context, domain string, check *entity.DomainDNSCheck) {
	records, err := c.resolver.LookupTXT(ctx, domain)
	if err != nil {
		slog.Debug("[DNS_CHECK] TXT lookup failed", "domain", domain, "error", err)
		check.SPFIssues = append(check.SPFIssues, "Failed to query DNS TXT records")
		return
	}

	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=spf1") {
			check.SPFExists = true
			check.SPFRecord = record
			check.SPFValid = c.validateSPF(record, check)
			break
		}
	}

	if !check.SPFExists {
		check.SPFIssues = append(check.SPFIssues, "No SPF record found - emails may be spoofed")
	}
}

// validateSPF validates SPF record syntax
func (c *DNSChecker) validateSPF(record string, check *entity.DomainDNSCheck) bool {
	valid := true
	record = strings.ToLower(record)

	// Check for common issues
	if !strings.HasPrefix(record, "v=spf1") {
		check.SPFIssues = append(check.SPFIssues, "Record does not start with v=spf1")
		valid = false
	}

	// Check for terminal mechanism
	hasAll := strings.Contains(record, "all")
	if !hasAll {
		check.SPFIssues = append(check.SPFIssues, "Missing 'all' mechanism at end")
		valid = false
	}

	// Warn about permissive +all
	if strings.Contains(record, "+all") {
		check.SPFIssues = append(check.SPFIssues, "Using +all allows any server to send - very insecure")
		valid = false
	}

	// Check length (SPF has 10 DNS lookup limit)
	lookupCount := strings.Count(record, "include:") +
		strings.Count(record, "redirect=") +
		strings.Count(record, "a:") +
		strings.Count(record, "mx:") +
		strings.Count(record, "ptr:")
	if lookupCount > 10 {
		check.SPFIssues = append(check.SPFIssues, fmt.Sprintf("Too many DNS lookups (%d > 10 limit)", lookupCount))
		valid = false
	}

	// Check for deprecated ptr mechanism
	if strings.Contains(record, "ptr") {
		check.SPFIssues = append(check.SPFIssues, "Using deprecated 'ptr' mechanism")
	}

	return valid
}

// checkDKIM checks for DKIM records
func (c *DNSChecker) checkDKIM(ctx context.Context, domain string, check *entity.DomainDNSCheck) {
	foundSelectors := []string{}

	for _, selector := range commonDKIMSelectors {
		dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
		records, err := c.resolver.LookupTXT(ctx, dkimDomain)
		if err != nil {
			continue
		}

		for _, record := range records {
			if strings.Contains(strings.ToLower(record), "v=dkim1") ||
				strings.Contains(strings.ToLower(record), "k=rsa") ||
				strings.Contains(strings.ToLower(record), "p=") {
				foundSelectors = append(foundSelectors, selector)
				break
			}
		}
	}

	if len(foundSelectors) > 0 {
		check.DKIMExists = true
		check.DKIMSelectors = foundSelectors
		check.DKIMValid = true
	} else {
		check.DKIMIssues = append(check.DKIMIssues, "No DKIM records found for common selectors")
	}
}

// checkDMARC checks for DMARC record
func (c *DNSChecker) checkDMARC(ctx context.Context, domain string, check *entity.DomainDNSCheck) {
	dmarcDomain := "_dmarc." + domain
	records, err := c.resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		slog.Debug("[DNS_CHECK] DMARC lookup failed", "domain", domain, "error", err)
		check.DMARCIssues = append(check.DMARCIssues, "No DMARC record found")
		return
	}

	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
			check.DMARCExists = true
			check.DMARCRecord = record
			check.DMARCValid = c.validateDMARC(record, check)
			break
		}
	}

	if !check.DMARCExists {
		check.DMARCIssues = append(check.DMARCIssues, "No DMARC record found - no policy enforcement")
	}
}

// validateDMARC validates DMARC record and extracts policy
func (c *DNSChecker) validateDMARC(record string, check *entity.DomainDNSCheck) bool {
	valid := true
	record = strings.ToLower(record)

	// Extract policy
	policyRegex := regexp.MustCompile(`p\s*=\s*(\w+)`)
	matches := policyRegex.FindStringSubmatch(record)
	if len(matches) > 1 {
		check.DMARCPolicy = matches[1]
	}

	// Validate policy
	switch check.DMARCPolicy {
	case "none":
		check.DMARCIssues = append(check.DMARCIssues, "Policy is 'none' - no enforcement, monitoring only")
		// Not invalid, just weak
	case "quarantine":
		// Good policy
	case "reject":
		// Best policy
	default:
		check.DMARCIssues = append(check.DMARCIssues, "Unknown or missing policy")
		valid = false
	}

	// Check for rua (aggregate reporting)
	if !strings.Contains(record, "rua=") {
		check.DMARCIssues = append(check.DMARCIssues, "No aggregate reporting (rua) configured")
	}

	// Check for ruf (forensic reporting)
	if !strings.Contains(record, "ruf=") {
		check.DMARCIssues = append(check.DMARCIssues, "No forensic reporting (ruf) configured")
	}

	// Check for subdomain policy
	if strings.Contains(record, "sp=") {
		spRegex := regexp.MustCompile(`sp\s*=\s*(\w+)`)
		spMatches := spRegex.FindStringSubmatch(record)
		if len(spMatches) > 1 && spMatches[1] == "none" {
			check.DMARCIssues = append(check.DMARCIssues, "Subdomain policy (sp) is 'none'")
		}
	}

	return valid
}

// calculateOverall calculates overall score and status
func (c *DNSChecker) calculateOverall(check *entity.DomainDNSCheck) {
	score := 0

	// MX Records (10 points)
	if check.MXExists {
		score += 10
	}

	// SPF (30 points)
	if check.SPFExists {
		score += 15
		if check.SPFValid {
			score += 15
		}
	}

	// DKIM (30 points)
	if check.DKIMExists {
		score += 15
		if check.DKIMValid {
			score += 15
		}
	}

	// DMARC (30 points)
	if check.DMARCExists {
		score += 10
		if check.DMARCValid {
			score += 10
		}
		// Bonus for strict policy
		switch check.DMARCPolicy {
		case "reject":
			score += 10
		case "quarantine":
			score += 5
		}
	}

	check.OverallScore = score

	// Determine status
	switch {
	case score >= 80:
		check.OverallStatus = "good"
	case score >= 50:
		check.OverallStatus = "warning"
	default:
		check.OverallStatus = "critical"
	}
}

// QuickCheck performs a quick check (just SPF and DMARC presence)
func (c *DNSChecker) QuickCheck(ctx context.Context, domain string) (hasSPF, hasDMARC bool, err error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Check SPF
	records, err := c.resolver.LookupTXT(ctx, domain)
	if err == nil {
		for _, record := range records {
			if strings.HasPrefix(strings.ToLower(record), "v=spf1") {
				hasSPF = true
				break
			}
		}
	}

	// Check DMARC
	dmarcDomain := "_dmarc." + domain
	records, err = c.resolver.LookupTXT(ctx, dmarcDomain)
	if err == nil {
		for _, record := range records {
			if strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
				hasDMARC = true
				break
			}
		}
	}

	return hasSPF, hasDMARC, nil
}
