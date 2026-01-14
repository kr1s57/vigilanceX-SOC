package clickhouse

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// ModSecRepository handles ModSec log operations in ClickHouse
type ModSecRepository struct {
	conn   *Connection
	logger *slog.Logger
}

// NewModSecRepository creates a new ModSec repository
func NewModSecRepository(conn *Connection, logger *slog.Logger) *ModSecRepository {
	return &ModSecRepository{
		conn:   conn,
		logger: logger,
	}
}

// GetLogs retrieves ModSec logs with filters and pagination
func (r *ModSecRepository) GetLogs(ctx context.Context, filters entity.ModSecLogFilters, limit, offset int) ([]entity.ModSecLog, uint64, error) {
	conditions := []string{"1=1"}
	args := []interface{}{}

	if filters.SrcIP != "" {
		conditions = append(conditions, "IPv4NumToString(src_ip) = ?")
		args = append(args, filters.SrcIP)
	}
	if filters.Hostname != "" {
		conditions = append(conditions, "hostname = ?")
		args = append(args, filters.Hostname)
	}
	if filters.RuleID != "" {
		conditions = append(conditions, "rule_id = ?")
		args = append(args, filters.RuleID)
	}
	if filters.AttackType != "" {
		conditions = append(conditions, "attack_type = ?")
		args = append(args, filters.AttackType)
	}
	if filters.UniqueID != "" {
		conditions = append(conditions, "unique_id = ?")
		args = append(args, filters.UniqueID)
	}
	if !filters.StartTime.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filters.StartTime)
	}
	if !filters.EndTime.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filters.EndTime)
	}
	if filters.SearchTerm != "" {
		conditions = append(conditions, "(rule_msg ILIKE ? OR uri ILIKE ? OR rule_data ILIKE ? OR rule_id ILIKE ? OR IPv4NumToString(src_ip) ILIKE ? OR hostname ILIKE ?)")
		searchPattern := "%" + filters.SearchTerm + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Get total count
	countQuery := fmt.Sprintf(`SELECT count() FROM modsec_logs WHERE %s`, whereClause)
	var total uint64
	if err := r.conn.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count modsec logs: %w", err)
	}

	// Get logs
	query := fmt.Sprintf(`
		SELECT
			toString(id), timestamp, unique_id, IPv4NumToString(src_ip) as src_ip,
			src_port, hostname, uri, rule_id, rule_file, rule_msg,
			rule_severity, rule_data, crs_version, paranoia_level,
			attack_type, total_score, is_blocking, tags, raw_log, ingested_at
		FROM modsec_logs
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	args = append(args, limit, offset)

	rows, err := r.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query modsec logs: %w", err)
	}
	defer rows.Close()

	var logs []entity.ModSecLog
	for rows.Next() {
		var l entity.ModSecLog
		var isBlockingInt uint8
		if err := rows.Scan(
			&l.ID, &l.Timestamp, &l.UniqueID, &l.SrcIP, &l.SrcPort,
			&l.Hostname, &l.URI, &l.RuleID, &l.RuleFile, &l.RuleMsg,
			&l.RuleSeverity, &l.RuleData, &l.CRSVersion, &l.ParanoiaLevel,
			&l.AttackType, &l.TotalScore, &isBlockingInt, &l.Tags, &l.RawLog, &l.IngestedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan modsec log: %w", err)
		}
		l.IsBlocking = isBlockingInt == 1
		logs = append(logs, l)
	}

	return logs, total, nil
}

// GetGroupedByRequest retrieves ModSec logs grouped by unique_id (request)
// Includes geolocation data and supports country search
func (r *ModSecRepository) GetGroupedByRequest(ctx context.Context, filters entity.ModSecLogFilters, limit, offset int) ([]entity.ModSecRequestGroup, uint64, error) {
	conditions := []string{"m.unique_id != ''"}
	args := []interface{}{}

	if filters.SrcIP != "" {
		conditions = append(conditions, "IPv4NumToString(m.src_ip) = ?")
		args = append(args, filters.SrcIP)
	}
	if filters.Hostname != "" {
		conditions = append(conditions, "m.hostname = ?")
		args = append(args, filters.Hostname)
	}
	if filters.RuleID != "" {
		conditions = append(conditions, "m.rule_id = ?")
		args = append(args, filters.RuleID)
	}
	if filters.AttackType != "" {
		conditions = append(conditions, "m.attack_type = ?")
		args = append(args, filters.AttackType)
	}
	if !filters.StartTime.IsZero() {
		conditions = append(conditions, "m.timestamp >= ?")
		args = append(args, filters.StartTime)
	}
	if !filters.EndTime.IsZero() {
		conditions = append(conditions, "m.timestamp <= ?")
		args = append(args, filters.EndTime)
	}
	if filters.Country != "" {
		// Country filter with LIKE for partial match (e.g., "India", "india", "IN")
		conditions = append(conditions, "(lower(g.country_name) LIKE ? OR lower(g.country_code) LIKE ?)")
		countryPattern := "%" + strings.ToLower(filters.Country) + "%"
		args = append(args, countryPattern, countryPattern)
	}
	if filters.SearchTerm != "" {
		// Search in rule data, URIs, IPs, hostnames, and country names
		conditions = append(conditions, "(lower(m.rule_msg) LIKE ? OR lower(m.uri) LIKE ? OR lower(m.rule_id) LIKE ? OR lower(IPv4NumToString(m.src_ip)) LIKE ? OR lower(m.hostname) LIKE ? OR lower(COALESCE(g.country_name, '')) LIKE ? OR lower(COALESCE(g.country_code, '')) LIKE ?)")
		searchPattern := "%" + strings.ToLower(filters.SearchTerm) + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Get total unique requests count with geo join
	// Note: Use explicit database prefix for JOIN tables (ClickHouse doesn't inherit default db in JOINs)
	countQuery := fmt.Sprintf(`
		SELECT count(DISTINCT m.unique_id)
		FROM vigilance_x.modsec_logs m
		LEFT JOIN vigilance_x.ip_geolocation g ON m.src_ip = g.ip
		WHERE %s
	`, whereClause)
	var total uint64
	if err := r.conn.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count unique requests: %w", err)
	}

	// Get grouped data with geolocation included
	query := fmt.Sprintf(`
		SELECT
			unique_id,
			min(timestamp) as first_timestamp,
			any(src_ip_str) as src_ip,
			any(hostname) as host,
			any(uri) as request_uri,
			max(total_score) as max_score,
			max(is_blocking) as blocked,
			count() as rules_count,
			groupArray(rule_id) as rule_ids,
			groupArray(rule_msg) as rule_msgs,
			groupArray(rule_severity) as rule_severities,
			groupArray(rule_file) as rule_files,
			groupArray(rule_data) as rule_datas,
			groupArray(attack_type) as attack_types,
			groupArray(paranoia_level) as paranoia_levels,
			groupArray(tags) as tags_arrays,
			any(geo_country) as geo_country,
			any(geo_city) as geo_city
		FROM (
			SELECT
				m.unique_id,
				m.timestamp,
				IPv4NumToString(m.src_ip) as src_ip_str,
				m.hostname,
				m.uri,
				m.total_score,
				m.is_blocking,
				m.rule_id,
				m.rule_msg,
				m.rule_severity,
				m.rule_file,
				m.rule_data,
				m.attack_type,
				m.paranoia_level,
				m.tags,
				COALESCE(g.country_code, '') as geo_country,
				COALESCE(g.city, '') as geo_city
			FROM vigilance_x.modsec_logs m
			LEFT JOIN vigilance_x.ip_geolocation g ON m.src_ip = g.ip
			WHERE %s
		)
		GROUP BY unique_id
		ORDER BY first_timestamp DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	args = append(args, limit, offset)

	rows, err := r.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query grouped modsec logs: %w", err)
	}
	defer rows.Close()

	var groups []entity.ModSecRequestGroup
	for rows.Next() {
		var g entity.ModSecRequestGroup
		var isBlockedInt uint8
		var ruleIDs, ruleMsgs, ruleSeverities, ruleFiles, ruleDatas, attackTypes []string
		var paranoiaLevels []uint8
		var tagsArrays [][]string

		if err := rows.Scan(
			&g.UniqueID, &g.Timestamp, &g.SrcIP, &g.Hostname, &g.URI,
			&g.TotalScore, &isBlockedInt, &g.RuleCount,
			&ruleIDs, &ruleMsgs, &ruleSeverities, &ruleFiles, &ruleDatas,
			&attackTypes, &paranoiaLevels, &tagsArrays,
			&g.GeoCountry, &g.GeoCity,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan grouped modsec log: %w", err)
		}

		g.IsBlocked = isBlockedInt == 1

		// Build rules list
		for i := range ruleIDs {
			rule := entity.ModSecRule{
				RuleID:       ruleIDs[i],
				RuleMsg:      ruleMsgs[i],
				RuleSeverity: ruleSeverities[i],
				RuleFile:     ruleFiles[i],
				RuleData:     ruleDatas[i],
			}
			if i < len(attackTypes) {
				rule.AttackType = attackTypes[i]
			}
			if i < len(paranoiaLevels) {
				rule.ParanoiaLevel = paranoiaLevels[i]
			}
			if i < len(tagsArrays) {
				rule.Tags = tagsArrays[i]
			}
			g.Rules = append(g.Rules, rule)
		}

		groups = append(groups, g)
	}

	return groups, total, nil
}

// GetUniqueHostnames returns unique hostnames from ModSec logs
func (r *ModSecRepository) GetUniqueHostnames(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT hostname
		FROM modsec_logs
		WHERE hostname != ''
		ORDER BY hostname
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query unique hostnames: %w", err)
	}
	defer rows.Close()

	var hostnames []string
	for rows.Next() {
		var hostname string
		if err := rows.Scan(&hostname); err != nil {
			return nil, fmt.Errorf("failed to scan hostname: %w", err)
		}
		hostnames = append(hostnames, hostname)
	}

	return hostnames, nil
}

// GetRuleStats returns statistics about ModSec rules
func (r *ModSecRepository) GetRuleStats(ctx context.Context, period string) ([]map[string]interface{}, error) {
	var startTime time.Time
	now := time.Now()

	switch period {
	case "24h":
		startTime = now.Add(-24 * time.Hour)
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		startTime = now.Add(-24 * time.Hour)
	}

	query := `
		SELECT
			rule_id,
			any(rule_msg) as rule_msg,
			count() as trigger_count,
			uniqExact(src_ip) as unique_ips,
			uniqExact(hostname) as unique_targets
		FROM modsec_logs
		WHERE timestamp >= ?
		GROUP BY rule_id
		ORDER BY trigger_count DESC
		LIMIT 50
	`

	rows, err := r.conn.Query(ctx, query, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query rule stats: %w", err)
	}
	defer rows.Close()

	var stats []map[string]interface{}
	for rows.Next() {
		var ruleID, ruleMsg string
		var triggerCount, uniqueIPs, uniqueTargets uint64
		if err := rows.Scan(&ruleID, &ruleMsg, &triggerCount, &uniqueIPs, &uniqueTargets); err != nil {
			return nil, fmt.Errorf("failed to scan rule stat: %w", err)
		}
		stats = append(stats, map[string]interface{}{
			"rule_id":        ruleID,
			"rule_msg":       ruleMsg,
			"trigger_count":  triggerCount,
			"unique_ips":     uniqueIPs,
			"unique_targets": uniqueTargets,
		})
	}

	return stats, nil
}

// GetAttackTypeStats returns statistics by attack type
func (r *ModSecRepository) GetAttackTypeStats(ctx context.Context, period string) ([]map[string]interface{}, error) {
	var startTime time.Time
	now := time.Now()

	switch period {
	case "24h":
		startTime = now.Add(-24 * time.Hour)
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		startTime = now.Add(-24 * time.Hour)
	}

	query := `
		SELECT
			attack_type,
			count() as count,
			uniqExact(src_ip) as unique_ips
		FROM modsec_logs
		WHERE timestamp >= ? AND attack_type != ''
		GROUP BY attack_type
		ORDER BY count DESC
	`

	rows, err := r.conn.Query(ctx, query, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query attack type stats: %w", err)
	}
	defer rows.Close()

	var stats []map[string]interface{}
	for rows.Next() {
		var attackType string
		var count, uniqueIPs uint64
		if err := rows.Scan(&attackType, &count, &uniqueIPs); err != nil {
			return nil, fmt.Errorf("failed to scan attack type stat: %w", err)
		}
		stats = append(stats, map[string]interface{}{
			"attack_type": attackType,
			"count":       count,
			"unique_ips":  uniqueIPs,
		})
	}

	return stats, nil
}
