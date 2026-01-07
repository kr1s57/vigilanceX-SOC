package clickhouse

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// DBStats represents database statistics
type DBStats struct {
	DatabaseSize   string            `json:"database_size"`
	TotalEvents    uint64            `json:"total_events"`
	EventsByType   map[string]uint64 `json:"events_by_type"`
	DateRangeStart time.Time         `json:"date_range_start"`
	DateRangeEnd   time.Time         `json:"date_range_end"`
	TableStats     []TableStat       `json:"table_stats"`
}

// TableStat represents statistics for a single table
type TableStat struct {
	TableName string `json:"table_name"`
	RowCount  uint64 `json:"row_count"`
	Size      string `json:"size"`
}

// StatsRepository handles database statistics queries
type StatsRepository struct {
	conn   driver.Conn
	logger *slog.Logger
}

// NewStatsRepository creates a new stats repository
func NewStatsRepository(conn driver.Conn, logger *slog.Logger) *StatsRepository {
	return &StatsRepository{
		conn:   conn,
		logger: logger,
	}
}

// GetDBStats retrieves comprehensive database statistics
func (r *StatsRepository) GetDBStats(ctx context.Context) (*DBStats, error) {
	stats := &DBStats{
		EventsByType: make(map[string]uint64),
	}

	// Get database size
	sizeQuery := `
		SELECT formatReadableSize(sum(bytes_on_disk)) as size
		FROM system.parts
		WHERE database = 'vigilance_x' AND active = 1
	`
	row := r.conn.QueryRow(ctx, sizeQuery)
	if err := row.Scan(&stats.DatabaseSize); err != nil {
		r.logger.Warn("Failed to get database size", "error", err)
		stats.DatabaseSize = "N/A"
	}

	// Get total events count
	totalQuery := `SELECT count() FROM events`
	row = r.conn.QueryRow(ctx, totalQuery)
	if err := row.Scan(&stats.TotalEvents); err != nil {
		r.logger.Warn("Failed to get total events", "error", err)
	}

	// Get events by log type
	byTypeQuery := `
		SELECT log_type, count() as cnt
		FROM events
		GROUP BY log_type
		ORDER BY cnt DESC
	`
	rows, err := r.conn.Query(ctx, byTypeQuery)
	if err != nil {
		r.logger.Warn("Failed to get events by type", "error", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var logType string
			var count uint64
			if err := rows.Scan(&logType, &count); err == nil {
				stats.EventsByType[logType] = count
			}
		}
	}

	// Get date range
	dateRangeQuery := `
		SELECT
			min(timestamp) as first_event,
			max(timestamp) as last_event
		FROM events
	`
	row = r.conn.QueryRow(ctx, dateRangeQuery)
	if err := row.Scan(&stats.DateRangeStart, &stats.DateRangeEnd); err != nil {
		r.logger.Warn("Failed to get date range", "error", err)
	}

	// Get table stats
	tableStatsQuery := `
		SELECT
			table as table_name,
			sum(rows) as row_count,
			formatReadableSize(sum(bytes_on_disk)) as size
		FROM system.parts
		WHERE database = 'vigilance_x' AND active = 1
		GROUP BY table
		ORDER BY sum(bytes_on_disk) DESC
	`
	rows, err = r.conn.Query(ctx, tableStatsQuery)
	if err != nil {
		r.logger.Warn("Failed to get table stats", "error", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var stat TableStat
			if err := rows.Scan(&stat.TableName, &stat.RowCount, &stat.Size); err == nil {
				stats.TableStats = append(stats.TableStats, stat)
			}
		}
	}

	return stats, nil
}

// ReportStats holds aggregated data for reports
type ReportStats struct {
	// Event statistics
	TotalEvents    uint64  `json:"total_events"`
	BlockedEvents  uint64  `json:"blocked_events"`
	BlockRate      float64 `json:"block_rate"`
	UniqueIPs      uint64  `json:"unique_ips"`
	CriticalEvents uint64  `json:"critical_events"`
	HighEvents     uint64  `json:"high_events"`
	MediumEvents   uint64  `json:"medium_events"`
	LowEvents      uint64  `json:"low_events"`

	// By type breakdown
	EventsByType     map[string]uint64 `json:"events_by_type"`
	EventsBySeverity map[string]uint64 `json:"events_by_severity"`
	EventsByAction   map[string]uint64 `json:"events_by_action"`

	// Top data
	TopAttackers []AttackerStat `json:"top_attackers"`
	TopTargets   []TargetStat   `json:"top_targets"`
	TopRules     []RuleStat     `json:"top_rules"`

	// Geographic data
	TopCountries []CountryStat `json:"top_countries"`
}

// AttackerStat represents statistics for an attacker IP
type AttackerStat struct {
	IP           string   `json:"ip"`
	AttackCount  uint64   `json:"attack_count"`
	BlockedCount uint64   `json:"blocked_count"`
	UniqueRules  uint64   `json:"unique_rules"`
	Categories   []string `json:"categories"`
	Country      string   `json:"country"`
}

// TargetStat represents statistics for a target
type TargetStat struct {
	Hostname    string `json:"hostname"`
	URL         string `json:"url"`
	AttackCount uint64 `json:"attack_count"`
	UniqueIPs   uint64 `json:"unique_ips"`
}

// RuleStat represents statistics for a rule
type RuleStat struct {
	RuleID       string `json:"rule_id"`
	RuleMsg      string `json:"rule_msg"`
	TriggerCount uint64 `json:"trigger_count"`
	UniqueIPs    uint64 `json:"unique_ips"`
}

// CountryStat represents statistics for a country
type CountryStat struct {
	Country     string `json:"country"`
	AttackCount uint64 `json:"attack_count"`
	UniqueIPs   uint64 `json:"unique_ips"`
}

// GetReportStats retrieves comprehensive stats for a report
func (r *StatsRepository) GetReportStats(ctx context.Context, startDate, endDate time.Time) (*ReportStats, error) {
	stats := &ReportStats{
		EventsByType:     make(map[string]uint64),
		EventsBySeverity: make(map[string]uint64),
		EventsByAction:   make(map[string]uint64),
	}

	// Main event statistics
	mainQuery := `
		SELECT
			count() as total_events,
			countIf(action = 'drop' OR action = 'reject' OR action = 'block') as blocked_events,
			uniqExact(src_ip) as unique_ips,
			countIf(severity = 'critical') as critical_events,
			countIf(severity = 'high') as high_events,
			countIf(severity = 'medium') as medium_events,
			countIf(severity = 'low') as low_events
		FROM events
		WHERE timestamp >= ? AND timestamp <= ?
	`
	row := r.conn.QueryRow(ctx, mainQuery, startDate, endDate)
	if err := row.Scan(
		&stats.TotalEvents,
		&stats.BlockedEvents,
		&stats.UniqueIPs,
		&stats.CriticalEvents,
		&stats.HighEvents,
		&stats.MediumEvents,
		&stats.LowEvents,
	); err != nil {
		return nil, fmt.Errorf("failed to get main stats: %w", err)
	}

	if stats.TotalEvents > 0 {
		stats.BlockRate = float64(stats.BlockedEvents) / float64(stats.TotalEvents) * 100
	}

	// Events by type
	byTypeQuery := `
		SELECT log_type, count() as cnt
		FROM events
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY log_type
		ORDER BY cnt DESC
	`
	rows, err := r.conn.Query(ctx, byTypeQuery, startDate, endDate)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var logType string
			var count uint64
			if err := rows.Scan(&logType, &count); err == nil {
				stats.EventsByType[logType] = count
			}
		}
	}

	// Events by severity
	bySeverityQuery := `
		SELECT severity, count() as cnt
		FROM events
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY severity
		ORDER BY cnt DESC
	`
	rows, err = r.conn.Query(ctx, bySeverityQuery, startDate, endDate)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var severity string
			var count uint64
			if err := rows.Scan(&severity, &count); err == nil {
				stats.EventsBySeverity[severity] = count
			}
		}
	}

	// Events by action
	byActionQuery := `
		SELECT action, count() as cnt
		FROM events
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY action
		ORDER BY cnt DESC
	`
	rows, err = r.conn.Query(ctx, byActionQuery, startDate, endDate)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var action string
			var count uint64
			if err := rows.Scan(&action, &count); err == nil {
				stats.EventsByAction[action] = count
			}
		}
	}

	// Top attackers
	attackersQuery := `
		SELECT
			IPv4NumToString(src_ip) as ip,
			count() as attack_count,
			countIf(action = 'drop' OR action = 'reject') as blocked_count,
			uniqExact(rule_id) as unique_rules,
			groupUniqArray(5)(category) as categories,
			any(geo_country) as country
		FROM events
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY src_ip
		ORDER BY attack_count DESC
		LIMIT 10
	`
	rows, err = r.conn.Query(ctx, attackersQuery, startDate, endDate)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var attacker AttackerStat
			if err := rows.Scan(
				&attacker.IP,
				&attacker.AttackCount,
				&attacker.BlockedCount,
				&attacker.UniqueRules,
				&attacker.Categories,
				&attacker.Country,
			); err == nil {
				stats.TopAttackers = append(stats.TopAttackers, attacker)
			}
		}
	}

	// Top targets
	targetsQuery := `
		SELECT
			hostname,
			any(url) as url,
			count() as attack_count,
			uniqExact(src_ip) as unique_ips
		FROM events
		WHERE timestamp >= ? AND timestamp <= ? AND hostname != ''
		GROUP BY hostname
		ORDER BY attack_count DESC
		LIMIT 10
	`
	rows, err = r.conn.Query(ctx, targetsQuery, startDate, endDate)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var target TargetStat
			if err := rows.Scan(
				&target.Hostname,
				&target.URL,
				&target.AttackCount,
				&target.UniqueIPs,
			); err == nil {
				stats.TopTargets = append(stats.TopTargets, target)
			}
		}
	}

	// Top rules
	rulesQuery := `
		SELECT
			rule_id,
			any(rule_name) as rule_msg,
			count() as trigger_count,
			uniqExact(src_ip) as unique_ips
		FROM events
		WHERE timestamp >= ? AND timestamp <= ? AND rule_id != ''
		GROUP BY rule_id
		ORDER BY trigger_count DESC
		LIMIT 10
	`
	rows, err = r.conn.Query(ctx, rulesQuery, startDate, endDate)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rule RuleStat
			if err := rows.Scan(
				&rule.RuleID,
				&rule.RuleMsg,
				&rule.TriggerCount,
				&rule.UniqueIPs,
			); err == nil {
				stats.TopRules = append(stats.TopRules, rule)
			}
		}
	}

	// Top countries
	countriesQuery := `
		SELECT
			geo_country as country,
			count() as attack_count,
			uniqExact(src_ip) as unique_ips
		FROM events
		WHERE timestamp >= ? AND timestamp <= ? AND geo_country != ''
		GROUP BY geo_country
		ORDER BY attack_count DESC
		LIMIT 10
	`
	rows, err = r.conn.Query(ctx, countriesQuery, startDate, endDate)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var country CountryStat
			if err := rows.Scan(
				&country.Country,
				&country.AttackCount,
				&country.UniqueIPs,
			); err == nil {
				stats.TopCountries = append(stats.TopCountries, country)
			}
		}
	}

	return stats, nil
}

// BanStats holds ban-related statistics
type BanStats struct {
	ActiveBans    uint64 `json:"active_bans"`
	PermanentBans uint64 `json:"permanent_bans"`
	ExpiredBans   uint64 `json:"expired_bans"`
	NewBans       uint64 `json:"new_bans"`
	Unbans        uint64 `json:"unbans"`
}

// GetBanStats retrieves ban statistics for a period
func (r *StatsRepository) GetBanStats(ctx context.Context, startDate, endDate time.Time) (*BanStats, error) {
	stats := &BanStats{}

	// Active and permanent bans
	activeQuery := `
		SELECT
			countIf(status = 'active') as active_bans,
			countIf(status = 'permanent') as permanent_bans,
			countIf(status = 'expired') as expired_bans
		FROM ip_ban_status
	`
	row := r.conn.QueryRow(ctx, activeQuery)
	if err := row.Scan(&stats.ActiveBans, &stats.PermanentBans, &stats.ExpiredBans); err != nil {
		r.logger.Warn("Failed to get ban status counts", "error", err)
	}

	// New bans in period
	newBansQuery := `
		SELECT count() FROM ban_history
		WHERE timestamp >= ? AND timestamp <= ? AND action = 'ban'
	`
	row = r.conn.QueryRow(ctx, newBansQuery, startDate, endDate)
	if err := row.Scan(&stats.NewBans); err != nil {
		r.logger.Warn("Failed to get new bans count", "error", err)
	}

	// Unbans in period
	unbansQuery := `
		SELECT count() FROM ban_history
		WHERE timestamp >= ? AND timestamp <= ? AND action = 'unban'
	`
	row = r.conn.QueryRow(ctx, unbansQuery, startDate, endDate)
	if err := row.Scan(&stats.Unbans); err != nil {
		r.logger.Warn("Failed to get unbans count", "error", err)
	}

	return stats, nil
}

// ThreatStats holds threat intelligence statistics
type ThreatStats struct {
	TotalTracked  uint64 `json:"total_tracked"`
	CriticalCount uint64 `json:"critical_count"`
	HighCount     uint64 `json:"high_count"`
	MediumCount   uint64 `json:"medium_count"`
	LowCount      uint64 `json:"low_count"`
	TorExitNodes  uint64 `json:"tor_exit_nodes"`
}

// GetThreatStats retrieves threat intelligence statistics
func (r *StatsRepository) GetThreatStats(ctx context.Context) (*ThreatStats, error) {
	stats := &ThreatStats{}

	query := `
		SELECT
			count() as total_tracked,
			countIf(threat_level = 'critical') as critical_count,
			countIf(threat_level = 'high') as high_count,
			countIf(threat_level = 'medium') as medium_count,
			countIf(threat_level = 'low') as low_count,
			countIf(abuseipdb_is_tor = 1) as tor_exit_nodes
		FROM ip_threat_scores
	`
	row := r.conn.QueryRow(ctx, query)
	if err := row.Scan(
		&stats.TotalTracked,
		&stats.CriticalCount,
		&stats.HighCount,
		&stats.MediumCount,
		&stats.LowCount,
		&stats.TorExitNodes,
	); err != nil {
		return nil, fmt.Errorf("failed to get threat stats: %w", err)
	}

	return stats, nil
}

// ModSecStats holds ModSecurity statistics
type ModSecStats struct {
	TotalLogs         uint64       `json:"total_logs"`
	BlockingLogs      uint64       `json:"blocking_logs"`
	UniqueRules       uint64       `json:"unique_rules"`
	TopAttackTypes    []AttackType `json:"top_attack_types"`
	TopTriggeredRules []RuleStat   `json:"top_triggered_rules"`
}

// AttackType represents an attack type with count
type AttackType struct {
	Type  string `json:"type"`
	Count uint64 `json:"count"`
}

// GetModSecStats retrieves ModSecurity statistics for a period
func (r *StatsRepository) GetModSecStats(ctx context.Context, startDate, endDate time.Time) (*ModSecStats, error) {
	stats := &ModSecStats{}

	// Main stats
	mainQuery := `
		SELECT
			count() as total_logs,
			countIf(is_blocking = 1) as blocking_logs,
			uniqExact(rule_id) as unique_rules
		FROM modsec_logs
		WHERE timestamp >= ? AND timestamp <= ?
	`
	row := r.conn.QueryRow(ctx, mainQuery, startDate, endDate)
	if err := row.Scan(&stats.TotalLogs, &stats.BlockingLogs, &stats.UniqueRules); err != nil {
		r.logger.Warn("Failed to get modsec main stats", "error", err)
	}

	// Top attack types
	attackTypesQuery := `
		SELECT attack_type, count() as cnt
		FROM modsec_logs
		WHERE timestamp >= ? AND timestamp <= ? AND attack_type != ''
		GROUP BY attack_type
		ORDER BY cnt DESC
		LIMIT 10
	`
	rows, err := r.conn.Query(ctx, attackTypesQuery, startDate, endDate)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var at AttackType
			if err := rows.Scan(&at.Type, &at.Count); err == nil {
				stats.TopAttackTypes = append(stats.TopAttackTypes, at)
			}
		}
	}

	// Top triggered rules
	rulesQuery := `
		SELECT
			rule_id,
			any(rule_msg) as rule_msg,
			count() as trigger_count,
			uniqExact(src_ip) as unique_ips
		FROM modsec_logs
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY rule_id
		ORDER BY trigger_count DESC
		LIMIT 10
	`
	rows, err = r.conn.Query(ctx, rulesQuery, startDate, endDate)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rule RuleStat
			if err := rows.Scan(&rule.RuleID, &rule.RuleMsg, &rule.TriggerCount, &rule.UniqueIPs); err == nil {
				stats.TopTriggeredRules = append(stats.TopTriggeredRules, rule)
			}
		}
	}

	return stats, nil
}

// VPNStats holds VPN statistics
type VPNStats struct {
	TotalEvents    uint64 `json:"total_events"`
	Connections    uint64 `json:"connections"`
	Disconnections uint64 `json:"disconnections"`
	AuthFailures   uint64 `json:"auth_failures"`
	UniqueUsers    uint64 `json:"unique_users"`
	TotalBytesIn   uint64 `json:"total_bytes_in"`
	TotalBytesOut  uint64 `json:"total_bytes_out"`
}

// GetVPNStats retrieves VPN statistics for a period
func (r *StatsRepository) GetVPNStats(ctx context.Context, startDate, endDate time.Time) (*VPNStats, error) {
	stats := &VPNStats{}

	// Count VPN events from main events table
	query := `
		SELECT
			count() as total_events,
			countIf(category = 'Connection' OR sub_category = 'connect') as connections,
			countIf(category = 'Disconnection' OR sub_category = 'disconnect') as disconnections,
			countIf(category = 'Auth Failure' OR sub_category = 'auth_fail') as auth_failures,
			uniqExact(user_name) as unique_users
		FROM events
		WHERE timestamp >= ? AND timestamp <= ? AND log_type = 'VPN'
	`
	row := r.conn.QueryRow(ctx, query, startDate, endDate)
	if err := row.Scan(
		&stats.TotalEvents,
		&stats.Connections,
		&stats.Disconnections,
		&stats.AuthFailures,
		&stats.UniqueUsers,
	); err != nil {
		r.logger.Warn("Failed to get VPN stats", "error", err)
	}

	return stats, nil
}
