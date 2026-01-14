package clickhouse

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// VigimailRepository handles Vigimail data persistence
type VigimailRepository struct {
	conn *Connection
}

// NewVigimailRepository creates a new repository instance
func NewVigimailRepository(conn *Connection) *VigimailRepository {
	return &VigimailRepository{conn: conn}
}

// ============================================
// Configuration
// ============================================

// GetConfig retrieves the current configuration
func (r *VigimailRepository) GetConfig(ctx context.Context) (*entity.VigimailConfig, error) {
	query := `
		SELECT
			enabled,
			check_interval_hours,
			hibp_api_key,
			leakcheck_api_key,
			last_check
		FROM vigilance_x.vigimail_config
		WHERE id = 1
		ORDER BY version DESC
		LIMIT 1
	`

	var enabled uint8
	var intervalHours uint8
	var hibpKey, leakCheckKey string
	var lastCheck time.Time

	row := r.conn.QueryRow(ctx, query)
	err := row.Scan(&enabled, &intervalHours, &hibpKey, &leakCheckKey, &lastCheck)
	if err != nil {
		slog.Warn("[VIGIMAIL_REPO] GetConfig failed, returning default", "error", err)
		return entity.DefaultVigimailConfig(), nil
	}

	return &entity.VigimailConfig{
		Enabled:            enabled == 1,
		CheckIntervalHours: int(intervalHours),
		HIBPAPIKey:         hibpKey,
		LeakCheckAPIKey:    leakCheckKey,
		LastCheck:          lastCheck,
	}, nil
}

// SaveConfig persists the configuration
func (r *VigimailRepository) SaveConfig(ctx context.Context, config *entity.VigimailConfig) error {
	var currentVersion uint64
	row := r.conn.QueryRow(ctx, "SELECT max(version) FROM vigilance_x.vigimail_config WHERE id = 1")
	if err := row.Scan(&currentVersion); err != nil {
		currentVersion = 0
	}

	enabled := uint8(0)
	if config.Enabled {
		enabled = 1
	}

	query := `
		INSERT INTO vigilance_x.vigimail_config (
			id, enabled, check_interval_hours, hibp_api_key, leakcheck_api_key,
			last_check, updated_at, version
		) VALUES (1, ?, ?, ?, ?, ?, now(), ?)
	`

	return r.conn.Exec(ctx, query,
		enabled,
		config.CheckIntervalHours,
		config.HIBPAPIKey,
		config.LeakCheckAPIKey,
		config.LastCheck,
		currentVersion+1,
	)
}

// UpdateLastCheck updates only the last_check timestamp
func (r *VigimailRepository) UpdateLastCheck(ctx context.Context, lastCheck time.Time) error {
	config, err := r.GetConfig(ctx)
	if err != nil {
		return err
	}
	config.LastCheck = lastCheck
	return r.SaveConfig(ctx, config)
}

// ============================================
// Domains
// ============================================

// ListDomains retrieves all monitored domains
func (r *VigimailRepository) ListDomains(ctx context.Context) ([]entity.VigimailDomain, error) {
	query := `
		SELECT id, domain, created_at
		FROM vigilance_x.vigimail_domains FINAL
		WHERE deleted = 0
		ORDER BY domain ASC
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	defer rows.Close()

	var domains []entity.VigimailDomain
	for rows.Next() {
		var d entity.VigimailDomain
		if err := rows.Scan(&d.ID, &d.Domain, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		domains = append(domains, d)
	}

	return domains, rows.Err()
}

// AddDomain adds a new domain to monitor
func (r *VigimailRepository) AddDomain(ctx context.Context, domain string) (*entity.VigimailDomain, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Check if already exists
	var count uint64
	row := r.conn.QueryRow(ctx, `
		SELECT count() FROM vigilance_x.vigimail_domains FINAL
		WHERE domain = ? AND deleted = 0
	`, domain)
	if err := row.Scan(&count); err == nil && count > 0 {
		return nil, fmt.Errorf("domain %s already exists", domain)
	}

	id := uuid.New().String()
	query := `
		INSERT INTO vigilance_x.vigimail_domains (id, domain, created_at, version)
		VALUES (?, ?, now(), 1)
	`

	if err := r.conn.Exec(ctx, query, id, domain); err != nil {
		return nil, fmt.Errorf("add domain: %w", err)
	}

	return &entity.VigimailDomain{
		ID:        id,
		Domain:    domain,
		CreatedAt: time.Now(),
	}, nil
}

// DeleteDomain soft-deletes a domain and its emails
func (r *VigimailRepository) DeleteDomain(ctx context.Context, domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Get current version
	var currentVersion uint64
	row := r.conn.QueryRow(ctx, `
		SELECT max(version) FROM vigilance_x.vigimail_domains WHERE domain = ?
	`, domain)
	row.Scan(&currentVersion)

	// Soft delete domain
	query := `
		INSERT INTO vigilance_x.vigimail_domains (id, domain, deleted, version)
		SELECT id, domain, 1, ?
		FROM vigilance_x.vigimail_domains FINAL
		WHERE domain = ? AND deleted = 0
	`
	if err := r.conn.Exec(ctx, query, currentVersion+1, domain); err != nil {
		return fmt.Errorf("delete domain: %w", err)
	}

	// Soft delete associated emails
	emailQuery := `
		INSERT INTO vigilance_x.vigimail_emails (id, email, domain, deleted, version)
		SELECT id, email, domain, 1, version + 1
		FROM vigilance_x.vigimail_emails FINAL
		WHERE domain = ? AND deleted = 0
	`
	return r.conn.Exec(ctx, emailQuery, domain)
}

// GetDomain retrieves a single domain
func (r *VigimailRepository) GetDomain(ctx context.Context, domain string) (*entity.VigimailDomain, error) {
	query := `
		SELECT id, domain, created_at
		FROM vigilance_x.vigimail_domains FINAL
		WHERE domain = ? AND deleted = 0
		LIMIT 1
	`

	var d entity.VigimailDomain
	row := r.conn.QueryRow(ctx, query, strings.ToLower(domain))
	if err := row.Scan(&d.ID, &d.Domain, &d.CreatedAt); err != nil {
		return nil, fmt.Errorf("domain not found: %w", err)
	}

	return &d, nil
}

// ============================================
// Emails
// ============================================

// ListEmails retrieves emails for a specific domain
func (r *VigimailRepository) ListEmails(ctx context.Context, domain string) ([]entity.VigimailEmail, error) {
	query := `
		SELECT id, email, domain, last_check, leak_count, status, created_at
		FROM vigilance_x.vigimail_emails FINAL
		WHERE domain = ? AND deleted = 0
		ORDER BY email ASC
	`

	rows, err := r.conn.Query(ctx, query, strings.ToLower(domain))
	if err != nil {
		return nil, fmt.Errorf("list emails: %w", err)
	}
	defer rows.Close()

	var emails []entity.VigimailEmail
	for rows.Next() {
		var e entity.VigimailEmail
		var leakCount uint32
		if err := rows.Scan(&e.ID, &e.Email, &e.Domain, &e.LastCheck, &leakCount, &e.Status, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan email: %w", err)
		}
		e.LeakCount = int(leakCount)
		emails = append(emails, e)
	}

	return emails, rows.Err()
}

// ListAllEmails retrieves all monitored emails
func (r *VigimailRepository) ListAllEmails(ctx context.Context) ([]entity.VigimailEmail, error) {
	query := `
		SELECT id, email, domain, last_check, leak_count, status, created_at
		FROM vigilance_x.vigimail_emails FINAL
		WHERE deleted = 0
		ORDER BY domain ASC, email ASC
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list all emails: %w", err)
	}
	defer rows.Close()

	var emails []entity.VigimailEmail
	for rows.Next() {
		var e entity.VigimailEmail
		var leakCount uint32
		if err := rows.Scan(&e.ID, &e.Email, &e.Domain, &e.LastCheck, &leakCount, &e.Status, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan email: %w", err)
		}
		e.LeakCount = int(leakCount)
		emails = append(emails, e)
	}

	return emails, rows.Err()
}

// AddEmail adds an email to monitor
func (r *VigimailRepository) AddEmail(ctx context.Context, email string) (*entity.VigimailEmail, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	// Extract domain
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email format: %s", email)
	}
	domain := parts[1]

	// Check if domain exists
	_, err := r.GetDomain(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("domain %s not registered, please add domain first", domain)
	}

	// Check if email already exists
	var count uint64
	row := r.conn.QueryRow(ctx, `
		SELECT count() FROM vigilance_x.vigimail_emails FINAL
		WHERE email = ? AND deleted = 0
	`, email)
	if err := row.Scan(&count); err == nil && count > 0 {
		return nil, fmt.Errorf("email %s already exists", email)
	}

	id := uuid.New().String()
	query := `
		INSERT INTO vigilance_x.vigimail_emails (id, email, domain, status, created_at, version)
		VALUES (?, ?, ?, 'pending', now(), 1)
	`

	if err := r.conn.Exec(ctx, query, id, email, domain); err != nil {
		return nil, fmt.Errorf("add email: %w", err)
	}

	return &entity.VigimailEmail{
		ID:        id,
		Email:     email,
		Domain:    domain,
		Status:    "pending",
		CreatedAt: time.Now(),
	}, nil
}

// DeleteEmail soft-deletes an email
func (r *VigimailRepository) DeleteEmail(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	var currentVersion uint64
	row := r.conn.QueryRow(ctx, `
		SELECT max(version) FROM vigilance_x.vigimail_emails WHERE email = ?
	`, email)
	row.Scan(&currentVersion)

	query := `
		INSERT INTO vigilance_x.vigimail_emails (id, email, domain, deleted, version)
		SELECT id, email, domain, 1, ?
		FROM vigilance_x.vigimail_emails FINAL
		WHERE email = ? AND deleted = 0
	`

	return r.conn.Exec(ctx, query, currentVersion+1, email)
}

// UpdateEmailStatus updates the status and leak count for an email
func (r *VigimailRepository) UpdateEmailStatus(ctx context.Context, email, status string, leakCount int) error {
	email = strings.ToLower(email)

	var currentVersion uint64
	row := r.conn.QueryRow(ctx, `
		SELECT max(version) FROM vigilance_x.vigimail_emails WHERE email = ?
	`, email)
	row.Scan(&currentVersion)

	query := `
		INSERT INTO vigilance_x.vigimail_emails (id, email, domain, last_check, leak_count, status, created_at, version)
		SELECT id, email, domain, now(), ?, ?, created_at, ?
		FROM vigilance_x.vigimail_emails FINAL
		WHERE email = ? AND deleted = 0
	`

	return r.conn.Exec(ctx, query, leakCount, status, currentVersion+1, email)
}

// ============================================
// Leaks
// ============================================

// GetLeaksForEmail retrieves all leaks for an email
func (r *VigimailRepository) GetLeaksForEmail(ctx context.Context, email string) ([]entity.VigimailLeak, error) {
	query := `
		SELECT id, email, source, breach_name, breach_date, data_classes,
		       is_verified, is_sensitive, description, first_seen, last_seen
		FROM vigilance_x.vigimail_leaks
		WHERE email = ?
		ORDER BY first_seen DESC
	`

	rows, err := r.conn.Query(ctx, query, strings.ToLower(email))
	if err != nil {
		return nil, fmt.Errorf("get leaks: %w", err)
	}
	defer rows.Close()

	var leaks []entity.VigimailLeak
	for rows.Next() {
		var l entity.VigimailLeak
		var breachDate *time.Time
		var isVerified, isSensitive uint8

		if err := rows.Scan(&l.ID, &l.Email, &l.Source, &l.BreachName, &breachDate,
			&l.DataClasses, &isVerified, &isSensitive, &l.Description, &l.FirstSeen, &l.LastSeen); err != nil {
			return nil, fmt.Errorf("scan leak: %w", err)
		}

		l.IsVerified = isVerified == 1
		l.IsSensitive = isSensitive == 1
		if breachDate != nil {
			dateStr := breachDate.Format("2006-01-02")
			l.BreachDate = &dateStr
		}

		leaks = append(leaks, l)
	}

	return leaks, rows.Err()
}

// SaveLeaks persists leak results (upsert by email+source+breach_name)
func (r *VigimailRepository) SaveLeaks(ctx context.Context, leaks []entity.VigimailLeak) error {
	if len(leaks) == 0 {
		return nil
	}

	for _, leak := range leaks {
		// Check if exists
		var count uint64
		row := r.conn.QueryRow(ctx, `
			SELECT count() FROM vigilance_x.vigimail_leaks
			WHERE email = ? AND source = ? AND breach_name = ?
		`, leak.Email, leak.Source, leak.BreachName)

		if err := row.Scan(&count); err == nil && count > 0 {
			// Update last_seen
			updateQuery := `
				ALTER TABLE vigilance_x.vigimail_leaks
				UPDATE last_seen = now()
				WHERE email = ? AND source = ? AND breach_name = ?
			`
			r.conn.Exec(ctx, updateQuery, leak.Email, leak.Source, leak.BreachName)
			continue
		}

		// Insert new
		var breachDate interface{} = nil
		if leak.BreachDate != nil && *leak.BreachDate != "" {
			breachDate = *leak.BreachDate
		}

		isVerified := uint8(0)
		if leak.IsVerified {
			isVerified = 1
		}
		isSensitive := uint8(0)
		if leak.IsSensitive {
			isSensitive = 1
		}

		query := `
			INSERT INTO vigilance_x.vigimail_leaks (
				id, email, source, breach_name, breach_date, data_classes,
				is_verified, is_sensitive, description, first_seen, last_seen
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, now(), now())
		`

		if err := r.conn.Exec(ctx, query,
			uuid.New().String(), leak.Email, leak.Source, leak.BreachName,
			breachDate, leak.DataClasses, isVerified, isSensitive, leak.Description,
		); err != nil {
			slog.Error("[VIGIMAIL_REPO] Failed to save leak", "email", leak.Email, "breach", leak.BreachName, "error", err)
		}
	}

	return nil
}

// ClearLeaksForEmail removes all leaks for an email (for re-scan)
func (r *VigimailRepository) ClearLeaksForEmail(ctx context.Context, email string) error {
	query := `ALTER TABLE vigilance_x.vigimail_leaks DELETE WHERE email = ?`
	return r.conn.Exec(ctx, query, strings.ToLower(email))
}

// ============================================
// DNS Checks
// ============================================

// GetLatestDomainCheck retrieves the most recent DNS check for a domain
func (r *VigimailRepository) GetLatestDomainCheck(ctx context.Context, domain string) (*entity.DomainDNSCheck, error) {
	query := `
		SELECT id, domain, check_time,
		       spf_exists, spf_record, spf_valid, spf_issues,
		       dkim_exists, dkim_selectors, dkim_valid, dkim_issues,
		       dmarc_exists, dmarc_record, dmarc_policy, dmarc_valid, dmarc_issues,
		       mx_exists, mx_records,
		       overall_score, overall_status
		FROM vigilance_x.vigimail_domain_checks
		WHERE domain = ?
		ORDER BY check_time DESC
		LIMIT 1
	`

	var d entity.DomainDNSCheck
	var spfExists, spfValid, dkimExists, dkimValid, dmarcExists, dmarcValid, mxExists uint8
	var overallScore uint8

	row := r.conn.QueryRow(ctx, query, strings.ToLower(domain))
	err := row.Scan(
		&d.ID, &d.Domain, &d.CheckTime,
		&spfExists, &d.SPFRecord, &spfValid, &d.SPFIssues,
		&dkimExists, &d.DKIMSelectors, &dkimValid, &d.DKIMIssues,
		&dmarcExists, &d.DMARCRecord, &d.DMARCPolicy, &dmarcValid, &d.DMARCIssues,
		&mxExists, &d.MXRecords,
		&overallScore, &d.OverallStatus,
	)
	if err != nil {
		return nil, fmt.Errorf("no DNS check found for domain: %w", err)
	}

	d.SPFExists = spfExists == 1
	d.SPFValid = spfValid == 1
	d.DKIMExists = dkimExists == 1
	d.DKIMValid = dkimValid == 1
	d.DMARCExists = dmarcExists == 1
	d.DMARCValid = dmarcValid == 1
	d.MXExists = mxExists == 1
	d.OverallScore = int(overallScore)

	return &d, nil
}

// SaveDomainCheck persists a DNS check result
func (r *VigimailRepository) SaveDomainCheck(ctx context.Context, check *entity.DomainDNSCheck) error {
	check.ID = uuid.New().String()
	check.CheckTime = time.Now()

	spfExists, spfValid := uint8(0), uint8(0)
	if check.SPFExists {
		spfExists = 1
	}
	if check.SPFValid {
		spfValid = 1
	}

	dkimExists, dkimValid := uint8(0), uint8(0)
	if check.DKIMExists {
		dkimExists = 1
	}
	if check.DKIMValid {
		dkimValid = 1
	}

	dmarcExists, dmarcValid := uint8(0), uint8(0)
	if check.DMARCExists {
		dmarcExists = 1
	}
	if check.DMARCValid {
		dmarcValid = 1
	}

	mxExists := uint8(0)
	if check.MXExists {
		mxExists = 1
	}

	query := `
		INSERT INTO vigilance_x.vigimail_domain_checks (
			id, domain, check_time,
			spf_exists, spf_record, spf_valid, spf_issues,
			dkim_exists, dkim_selectors, dkim_valid, dkim_issues,
			dmarc_exists, dmarc_record, dmarc_policy, dmarc_valid, dmarc_issues,
			mx_exists, mx_records,
			overall_score, overall_status
		) VALUES (?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	return r.conn.Exec(ctx, query,
		check.ID, strings.ToLower(check.Domain),
		spfExists, check.SPFRecord, spfValid, check.SPFIssues,
		dkimExists, check.DKIMSelectors, dkimValid, check.DKIMIssues,
		dmarcExists, check.DMARCRecord, check.DMARCPolicy, dmarcValid, check.DMARCIssues,
		mxExists, check.MXRecords,
		check.OverallScore, check.OverallStatus,
	)
}

// GetDomainCheckHistory retrieves DNS check history for a domain
func (r *VigimailRepository) GetDomainCheckHistory(ctx context.Context, domain string, limit int) ([]entity.DomainDNSCheck, error) {
	if limit <= 0 {
		limit = 10
	}

	query := `
		SELECT id, domain, check_time, overall_score, overall_status
		FROM vigilance_x.vigimail_domain_checks
		WHERE domain = ?
		ORDER BY check_time DESC
		LIMIT ?
	`

	rows, err := r.conn.Query(ctx, query, strings.ToLower(domain), limit)
	if err != nil {
		return nil, fmt.Errorf("get DNS history: %w", err)
	}
	defer rows.Close()

	var checks []entity.DomainDNSCheck
	for rows.Next() {
		var c entity.DomainDNSCheck
		var overallScore uint8
		if err := rows.Scan(&c.ID, &c.Domain, &c.CheckTime, &overallScore, &c.OverallStatus); err != nil {
			return nil, fmt.Errorf("scan DNS check: %w", err)
		}
		c.OverallScore = int(overallScore)
		checks = append(checks, c)
	}

	return checks, rows.Err()
}

// ============================================
// Statistics
// ============================================

// GetStats retrieves aggregated statistics
func (r *VigimailRepository) GetStats(ctx context.Context) (*entity.VigimailStats, error) {
	stats := &entity.VigimailStats{
		LeaksBySource: make(map[string]int),
	}

	var cnt uint64

	// Count domains
	row := r.conn.QueryRow(ctx, `SELECT count() FROM vigilance_x.vigimail_domains FINAL WHERE deleted = 0`)
	if row.Scan(&cnt) == nil {
		stats.TotalDomains = int(cnt)
	}

	// Count emails by status
	row = r.conn.QueryRow(ctx, `SELECT count() FROM vigilance_x.vigimail_emails FINAL WHERE deleted = 0`)
	if row.Scan(&cnt) == nil {
		stats.TotalEmails = int(cnt)
	}

	row = r.conn.QueryRow(ctx, `SELECT count() FROM vigilance_x.vigimail_emails FINAL WHERE deleted = 0 AND status = 'clean'`)
	if row.Scan(&cnt) == nil {
		stats.EmailsClean = int(cnt)
	}

	row = r.conn.QueryRow(ctx, `SELECT count() FROM vigilance_x.vigimail_emails FINAL WHERE deleted = 0 AND status = 'leaked'`)
	if row.Scan(&cnt) == nil {
		stats.EmailsWithLeaks = int(cnt)
	}

	row = r.conn.QueryRow(ctx, `SELECT count() FROM vigilance_x.vigimail_emails FINAL WHERE deleted = 0 AND status = 'pending'`)
	if row.Scan(&cnt) == nil {
		stats.EmailsPending = int(cnt)
	}

	// Count total leaks
	row = r.conn.QueryRow(ctx, `SELECT count() FROM vigilance_x.vigimail_leaks`)
	if row.Scan(&cnt) == nil {
		stats.TotalLeaks = int(cnt)
	}

	// Leaks by source
	rows, err := r.conn.Query(ctx, `SELECT source, count() as cnt FROM vigilance_x.vigimail_leaks GROUP BY source`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var source string
			var cnt uint64
			if rows.Scan(&source, &cnt) == nil {
				stats.LeaksBySource[source] = int(cnt)
			}
		}
	}

	// Top breaches
	rows, err = r.conn.Query(ctx, `
		SELECT breach_name, count() as cnt, min(breach_date) as first_date
		FROM vigilance_x.vigimail_leaks
		GROUP BY breach_name
		ORDER BY cnt DESC
		LIMIT 10
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var bs entity.BreachStat
			var date *time.Time
			var affectedCnt uint64
			if rows.Scan(&bs.Name, &affectedCnt, &date) == nil {
				bs.AffectedCount = int(affectedCnt)
				if date != nil {
					bs.Date = date.Format("2006-01-02")
				}
				stats.TopBreaches = append(stats.TopBreaches, bs)
			}
		}
	}

	// DNS status counts (from latest checks per domain)
	rows, err = r.conn.Query(ctx, `
		SELECT overall_status, count() as cnt
		FROM (
			SELECT domain, argMax(overall_status, check_time) as overall_status
			FROM vigilance_x.vigimail_domain_checks
			GROUP BY domain
		)
		GROUP BY overall_status
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var status string
			var cnt uint64
			if rows.Scan(&status, &cnt) == nil {
				switch status {
				case "good":
					stats.DomainsGood = int(cnt)
				case "warning":
					stats.DomainsWarning = int(cnt)
				case "critical":
					stats.DomainsCritical = int(cnt)
				}
			}
		}
	}

	return stats, nil
}

// SaveCheckHistory persists a check execution record
func (r *VigimailRepository) SaveCheckHistory(ctx context.Context, history *entity.VigimailCheckHistory) error {
	success := uint8(0)
	if history.Success {
		success = 1
	}

	query := `
		INSERT INTO vigilance_x.vigimail_check_history (
			id, check_time, check_type, emails_checked, domains_checked,
			leaks_found, dns_issues_found, duration_ms, success, error
		) VALUES (?, now(), ?, ?, ?, ?, ?, ?, ?, ?)
	`

	return r.conn.Exec(ctx, query,
		uuid.New().String(), history.CheckType, history.EmailsChecked, history.DomainsChecked,
		history.LeaksFound, history.DNSIssuesFound, history.DurationMS, success, history.Error,
	)
}
