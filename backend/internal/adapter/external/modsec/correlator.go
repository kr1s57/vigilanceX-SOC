package modsec

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Correlator matches ModSec logs with ClickHouse events
type Correlator struct {
	db     driver.Conn
	logger *slog.Logger
}

// NewCorrelator creates a new correlator
func NewCorrelator(db driver.Conn, logger *slog.Logger) *Correlator {
	return &Correlator{
		db:     db,
		logger: logger,
	}
}

// ruleData holds both rule ID and message for correlation
type ruleData struct {
	RuleID  string
	Message string
}

// CorrelateAndUpdate finds matching events and updates their modsec_rule_ids and modsec_messages
func (c *Correlator) CorrelateAndUpdate(ctx context.Context, entries []LogEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	updated := 0

	// Group entries by source IP and timestamp window for efficient matching
	type correlationKey struct {
		SrcIP     string
		Hostname  string
		Timestamp time.Time
	}

	// Build a map of entries grouped by key (now with messages)
	entryMap := make(map[correlationKey][]ruleData) // key -> rule data (ID + message)
	for _, entry := range entries {
		// Round timestamp to the nearest second for matching
		roundedTime := entry.Timestamp.Truncate(time.Second)
		key := correlationKey{
			SrcIP:     entry.SrcIP,
			Hostname:  entry.Hostname,
			Timestamp: roundedTime,
		}
		entryMap[key] = append(entryMap[key], ruleData{
			RuleID:  entry.RuleID,
			Message: entry.Message,
		})
	}

	// For each unique key, find matching events and update
	for key, rules := range entryMap {
		// Remove duplicates and build parallel arrays for IDs and messages
		uniqueRules, uniqueMessages := uniqueRulesWithMessages(rules)

		// Find events within a wider 30-second window to account for timing differences
		startTime := key.Timestamp.Add(-30 * time.Second)
		endTime := key.Timestamp.Add(30 * time.Second)

		// Update events matching the criteria (now with messages)
		query := `
			ALTER TABLE vigilance_x.events
			UPDATE modsec_rule_ids = ?, modsec_messages = ?
			WHERE log_type = 'WAF'
			  AND src_ip = toIPv4(?)
			  AND hostname = ?
			  AND timestamp BETWEEN ? AND ?
			  AND length(modsec_rule_ids) = 0
		`

		err := c.db.Exec(ctx, query, uniqueRules, uniqueMessages, key.SrcIP, key.Hostname, startTime, endTime)
		if err != nil {
			c.logger.Warn("Failed to update event", "error", err, "src_ip", key.SrcIP, "hostname", key.Hostname)
			continue
		}
		updated++
	}

	return updated, nil
}

// CorrelateByURI performs more precise correlation using URI
func (c *Correlator) CorrelateByURI(ctx context.Context, entries []LogEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	updated := 0

	for _, entry := range entries {
		if entry.URI == "" || entry.SrcIP == "" || entry.RuleID == "" {
			continue
		}

		// Time window: +/- 2 seconds from ModSec timestamp
		startTime := entry.Timestamp.Add(-2 * time.Second)
		endTime := entry.Timestamp.Add(2 * time.Second)

		// Build the arrays of rule IDs and messages to add
		ruleIDs := []string{entry.RuleID}
		messages := []string{entry.Message}

		// Update matching event (now with messages)
		query := `
			ALTER TABLE vigilance_x.events
			UPDATE modsec_rule_ids = arrayConcat(modsec_rule_ids, ?),
			       modsec_messages = arrayConcat(modsec_messages, ?)
			WHERE log_type = 'WAF'
			  AND src_ip = toIPv4(?)
			  AND hostname = ?
			  AND url LIKE ?
			  AND timestamp BETWEEN ? AND ?
			  AND NOT has(modsec_rule_ids, ?)
		`

		uriPattern := "%" + entry.URI + "%"
		err := c.db.Exec(ctx, query, ruleIDs, messages, entry.SrcIP, entry.Hostname, uriPattern, startTime, endTime, entry.RuleID)
		if err != nil {
			c.logger.Warn("Failed to update event by URI", "error", err, "uri", entry.URI)
			continue
		}
		updated++
	}

	return updated, nil
}

// GetLastSyncTime returns the timestamp of the most recent ModSec-enriched event
func (c *Correlator) GetLastSyncTime(ctx context.Context) (time.Time, error) {
	var lastTime time.Time
	query := `
		SELECT max(timestamp)
		FROM vigilance_x.events
		WHERE log_type = 'WAF' AND length(modsec_rule_ids) > 0
	`
	err := c.db.QueryRow(ctx, query).Scan(&lastTime)
	if err != nil {
		return time.Time{}, err
	}
	return lastTime, nil
}

// GetEventsNeedingEnrichment returns events that don't have ModSec rule IDs
func (c *Correlator) GetEventsNeedingEnrichment(ctx context.Context, since time.Time, limit int) ([]EventForEnrichment, error) {
	query := `
		SELECT event_id, timestamp, IPv4NumToString(src_ip) as src_ip, hostname, url
		FROM vigilance_x.events
		WHERE log_type = 'WAF'
		  AND action = 'drop'
		  AND timestamp >= ?
		  AND length(modsec_rule_ids) = 0
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := c.db.Query(ctx, query, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []EventForEnrichment
	for rows.Next() {
		var e EventForEnrichment
		if err := rows.Scan(&e.EventID, &e.Timestamp, &e.SrcIP, &e.Hostname, &e.URL); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, e)
	}

	return events, nil
}

// EventForEnrichment represents an event that needs ModSec enrichment
type EventForEnrichment struct {
	EventID   string
	Timestamp time.Time
	SrcIP     string
	Hostname  string
	URL       string
}

// uniqueStrings removes duplicates from a string slice
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(input))
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// uniqueRulesWithMessages removes duplicates while keeping rule IDs and messages in sync
// Returns two parallel arrays: unique rule IDs and their corresponding messages
func uniqueRulesWithMessages(input []ruleData) ([]string, []string) {
	seen := make(map[string]bool)
	ruleIDs := make([]string, 0, len(input))
	messages := make([]string, 0, len(input))
	for _, rd := range input {
		if !seen[rd.RuleID] {
			seen[rd.RuleID] = true
			ruleIDs = append(ruleIDs, rd.RuleID)
			messages = append(messages, rd.Message)
		}
	}
	return ruleIDs, messages
}

// StoreModSecLogs stores parsed ModSec log entries directly in modsec_logs table
func (c *Correlator) StoreModSecLogs(ctx context.Context, entries []LogEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	// Prepare batch insert
	query := `
		INSERT INTO vigilance_x.modsec_logs (
			timestamp, unique_id, src_ip, src_port, hostname, uri,
			rule_id, rule_file, rule_msg, rule_severity, rule_data,
			crs_version, paranoia_level, attack_type,
			total_score, is_blocking, tags, raw_log
		) VALUES (?, ?, toIPv4(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	batch, err := c.db.PrepareBatch(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to prepare batch: %w", err)
	}

	inserted := 0
	for _, entry := range entries {
		srcPort := uint16(0)
		if port, err := strconv.Atoi(entry.SrcPort); err == nil {
			srcPort = uint16(port)
		}

		isBlocking := uint8(0)
		if entry.IsBlocking {
			isBlocking = 1
		}

		err := batch.Append(
			entry.Timestamp,
			entry.UniqueID,
			entry.SrcIP,
			srcPort,
			entry.Hostname,
			entry.URI,
			entry.RuleID,
			entry.RuleFile,
			entry.Message,
			entry.Severity,
			entry.RuleData,
			entry.CRSVersion,
			uint8(entry.ParanoiaLevel),
			entry.AttackType,
			uint16(entry.TotalScore),
			isBlocking,
			entry.Tags,
			entry.FullLog,
		)
		if err != nil {
			c.logger.Warn("Failed to append entry to batch", "error", err, "rule_id", entry.RuleID)
			continue
		}
		inserted++
	}

	if err := batch.Send(); err != nil {
		return 0, fmt.Errorf("failed to send batch: %w", err)
	}

	c.logger.Info("Stored ModSec logs", "count", inserted)
	return inserted, nil
}
