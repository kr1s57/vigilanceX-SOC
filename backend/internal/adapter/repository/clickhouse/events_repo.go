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

// EventsRepository handles event data operations in ClickHouse
type EventsRepository struct {
	conn   *Connection
	logger *slog.Logger
}

// NewEventsRepository creates a new events repository
func NewEventsRepository(conn *Connection, logger *slog.Logger) *EventsRepository {
	return &EventsRepository{
		conn:   conn,
		logger: logger,
	}
}

// GetEvents retrieves events with filters and pagination
func (r *EventsRepository) GetEvents(ctx context.Context, filters entity.EventFilters, limit, offset int) ([]entity.Event, uint64, error) {
	// Build WHERE clause
	conditions := []string{"1=1"}
	args := []interface{}{}

	// v3.55.101: Use e. prefix for all conditions to reference table columns
	if filters.LogType != "" {
		conditions = append(conditions, "e.log_type = ?")
		args = append(args, filters.LogType)
	}
	if filters.Category != "" {
		conditions = append(conditions, "e.category = ?")
		args = append(args, filters.Category)
	}
	if filters.Severity != "" {
		conditions = append(conditions, "e.severity = ?")
		args = append(args, filters.Severity)
	}
	if filters.SrcIP != "" {
		// v3.55.101: Use e. prefix to reference table column, not SELECT alias
		conditions = append(conditions, "e.src_ip = toIPv4(?)")
		args = append(args, filters.SrcIP)
	}
	if filters.DstIP != "" {
		conditions = append(conditions, "e.dst_ip = toIPv4(?)")
		args = append(args, filters.DstIP)
	}
	if filters.Hostname != "" {
		conditions = append(conditions, "e.hostname = ?")
		args = append(args, filters.Hostname)
	}
	if filters.RuleID != "" {
		conditions = append(conditions, "e.rule_id = ?")
		args = append(args, filters.RuleID)
	}
	if filters.Action != "" {
		conditions = append(conditions, "e.action = ?")
		args = append(args, filters.Action)
	}
	if !filters.StartTime.IsZero() {
		conditions = append(conditions, "e.timestamp >= ?")
		args = append(args, filters.StartTime)
	}
	if !filters.EndTime.IsZero() {
		conditions = append(conditions, "e.timestamp <= ?")
		args = append(args, filters.EndTime)
	}
	if filters.SearchTerm != "" {
		conditions = append(conditions, "(e.message ILIKE ? OR e.rule_name ILIKE ? OR e.url ILIKE ?)")
		searchPattern := "%" + filters.SearchTerm + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Get total count
	countQuery := fmt.Sprintf(`SELECT count() FROM events e WHERE %s`, whereClause)
	var total uint64
	if err := r.conn.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count events: %w", err)
	}

	// Get events
	// v3.55.101: Use explicit table prefix e. to avoid alias collision with IPv4NumToString
	// v3.57.113: Added mitre_technique for MITRE ATT&CK detection
	query := fmt.Sprintf(`
		SELECT
			e.event_id, e.timestamp, e.log_type, e.category, e.sub_category, e.severity,
			e.mitre_technique,
			IPv4NumToString(e.src_ip) as src_ip, IPv4NumToString(e.dst_ip) as dst_ip,
			e.src_port, e.dst_port, e.protocol, e.action, e.rule_id, e.rule_name,
			e.hostname, e.user_name, e.url, e.http_method, e.http_status, e.user_agent,
			e.geo_country, e.geo_city, e.geo_asn, e.geo_org, e.message, e.reason, e.sophos_id, e.ingested_at,
			e.modsec_rule_ids, e.modsec_messages
		FROM events e
		WHERE %s
		ORDER BY e.timestamp DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	args = append(args, limit, offset)

	rows, err := r.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	events := []entity.Event{}
	for rows.Next() {
		var e entity.Event
		if err := rows.Scan(
			&e.EventID, &e.Timestamp, &e.LogType, &e.Category, &e.SubCategory, &e.Severity,
			&e.MitreTechnique,
			&e.SrcIP, &e.DstIP, &e.SrcPort, &e.DstPort, &e.Protocol, &e.Action,
			&e.RuleID, &e.RuleName, &e.Hostname, &e.UserName, &e.URL, &e.HTTPMethod,
			&e.HTTPStatus, &e.UserAgent, &e.GeoCountry, &e.GeoCity, &e.GeoASN,
			&e.GeoOrg, &e.Message, &e.Reason, &e.SophosID, &e.IngestedAt,
			&e.ModSecRuleIDs, &e.ModSecMessages,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, e)
	}

	return events, total, nil
}

// GetEventByID retrieves a single event by ID
// v3.57.113: Added mitre_technique for MITRE ATT&CK detection
func (r *EventsRepository) GetEventByID(ctx context.Context, eventID uuid.UUID) (*entity.Event, error) {
	query := `
		SELECT
			event_id, timestamp, log_type, category, sub_category, severity,
			mitre_technique,
			IPv4NumToString(src_ip) as src_ip, IPv4NumToString(dst_ip) as dst_ip,
			src_port, dst_port, protocol, action, rule_id, rule_name,
			hostname, user_name, url, http_method, http_status, user_agent,
			geo_country, geo_city, geo_asn, geo_org, message, reason, raw_log, sophos_id, ingested_at,
			modsec_rule_ids, modsec_messages
		FROM events
		WHERE event_id = ?
		LIMIT 1
	`

	var e entity.Event
	if err := r.conn.QueryRow(ctx, query, eventID).Scan(
		&e.EventID, &e.Timestamp, &e.LogType, &e.Category, &e.SubCategory, &e.Severity,
		&e.MitreTechnique,
		&e.SrcIP, &e.DstIP, &e.SrcPort, &e.DstPort, &e.Protocol, &e.Action,
		&e.RuleID, &e.RuleName, &e.Hostname, &e.UserName, &e.URL, &e.HTTPMethod,
		&e.HTTPStatus, &e.UserAgent, &e.GeoCountry, &e.GeoCity, &e.GeoASN,
		&e.GeoOrg, &e.Message, &e.Reason, &e.RawLog, &e.SophosID, &e.IngestedAt,
		&e.ModSecRuleIDs, &e.ModSecMessages,
	); err != nil {
		return nil, fmt.Errorf("failed to get event: %w", err)
	}

	return &e, nil
}

// GetTimeline retrieves event timeline data
func (r *EventsRepository) GetTimeline(ctx context.Context, period string, interval string) ([]entity.TimelinePoint, error) {
	// Calculate time range
	var startTime time.Time
	now := time.Now()

	switch period {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "8h": // v3.57.117: Added 8h period
		startTime = now.Add(-8 * time.Hour)
	case "24h":
		startTime = now.Add(-24 * time.Hour)
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		startTime = now.Add(-24 * time.Hour)
	}

	// Determine grouping function
	var timeFunc string
	switch interval {
	case "hour":
		timeFunc = "toStartOfHour(timestamp)"
	case "day":
		timeFunc = "toStartOfDay(timestamp)"
	default:
		timeFunc = "toStartOfHour(timestamp)"
	}

	// v3.57.114: Exclude infrastructure IP 83.194.220.184 from timeline
	query := fmt.Sprintf(`
		SELECT
			%s as time_bucket,
			count() as total_events,
			countIf(action IN ('drop', 'reject', 'block', 'blocked')) as blocked_events,
			uniqExact(src_ip) as unique_ips
		FROM events
		WHERE timestamp >= ?
			AND src_ip != toIPv4('83.194.220.184')
		GROUP BY time_bucket
		ORDER BY time_bucket ASC
	`, timeFunc)

	rows, err := r.conn.Query(ctx, query, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query timeline: %w", err)
	}
	defer rows.Close()

	timeline := []entity.TimelinePoint{}
	for rows.Next() {
		var point entity.TimelinePoint
		if err := rows.Scan(&point.Time, &point.TotalEvents, &point.BlockedEvents, &point.UniqueIPs); err != nil {
			return nil, fmt.Errorf("failed to scan timeline point: %w", err)
		}
		timeline = append(timeline, point)
	}

	return timeline, nil
}

// GetStats retrieves event statistics
// v3.57.101: Combines events table with modsec_logs for accurate WAF blocking stats
func (r *EventsRepository) GetStats(ctx context.Context, period string) (*entity.EventStats, error) {
	var startTime time.Time
	now := time.Now()

	switch period {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "8h": // v3.57.117: Added 8h period
		startTime = now.Add(-8 * time.Hour)
	case "24h":
		startTime = now.Add(-24 * time.Hour)
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		startTime = now.Add(-24 * time.Hour)
	}

	// Main events table stats
	// v3.57.114: Exclude infrastructure IP 83.194.220.184 from stats
	query := `
		SELECT
			count() as total_events,
			countIf(action IN ('drop', 'reject', 'block', 'blocked')) as blocked_events,
			uniqExact(src_ip) as unique_ips,
			countIf(severity = 'critical') as critical_events,
			countIf(severity = 'high') as high_events,
			countIf(severity = 'medium') as medium_events,
			countIf(severity = 'low') as low_events
		FROM events
		WHERE timestamp >= ?
			AND src_ip != toIPv4('83.194.220.184')
	`

	var stats entity.EventStats
	if err := r.conn.QueryRow(ctx, query, startTime).Scan(
		&stats.TotalEvents,
		&stats.BlockedEvents,
		&stats.UniqueIPs,
		&stats.CriticalEvents,
		&stats.HighEvents,
		&stats.MediumEvents,
		&stats.LowEvents,
	); err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	// v3.57.101: Add modsec_logs stats for WAF blocking/severity data
	// This is where the real WAF blocking info lives (is_blocking, rule_severity)
	// v3.57.114: Exclude infrastructure IP 83.194.220.184 from stats
	modsecQuery := `
		SELECT
			countIf(is_blocking = 1) as blocked,
			countIf(rule_severity = 'CRITICAL') as critical,
			countIf(rule_severity = 'WARNING' OR rule_severity = 'ERROR') as high
		FROM modsec_logs
		WHERE timestamp >= ?
			AND src_ip != toIPv4('83.194.220.184')
	`
	var modsecBlocked, modsecCritical, modsecHigh uint64
	if err := r.conn.QueryRow(ctx, modsecQuery, startTime).Scan(
		&modsecBlocked,
		&modsecCritical,
		&modsecHigh,
	); err == nil {
		// Add modsec stats to totals
		stats.BlockedEvents += modsecBlocked
		stats.CriticalEvents += modsecCritical
		stats.HighEvents += modsecHigh
	}

	if stats.TotalEvents > 0 {
		stats.BlockRate = float64(stats.BlockedEvents) / float64(stats.TotalEvents) * 100
	}

	return &stats, nil
}

// GetTopAttackers retrieves top attacking IPs
// v3.57.108: Filters out private/LAN IPs and only shows real attackers with security events
func (r *EventsRepository) GetTopAttackers(ctx context.Context, period string, limit int) ([]entity.TopAttacker, error) {
	var startTime time.Time
	now := time.Now()

	switch period {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "8h": // v3.57.117: Added 8h period
		startTime = now.Add(-8 * time.Hour)
	case "24h":
		startTime = now.Add(-24 * time.Hour)
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		startTime = now.Add(-24 * time.Hour)
	}

	// v3.57.108: Filter out private IP ranges (RFC1918 + loopback)
	// v3.57.110: Also filter out XGS public IP (83.194.220.184) and VGX infrastructure IPs
	// v3.57.113: Added 178.18.1.0/24 internal management network exclusion
	// Only include security-relevant log types (WAF, IPS, ATP, Anti-Virus, Firewall attacks)
	// Exclude generic events like Heartbeat, Admin, etc.
	query := `
		SELECT
			IPv4NumToString(src_ip) as ip,
			toInt64(count()) as attack_count,
			toInt64(countIf(action IN ('drop', 'reject', 'block', 'blocked', 'deny'))) as blocked_count,
			toInt64(uniqExact(rule_id)) as unique_rules,
			groupUniqArray(5)(category) as categories,
			any(geo_country) as country
		FROM events
		WHERE timestamp >= ?
		  AND src_ip != toIPv4('0.0.0.0')
		  AND (src_ip < toIPv4('10.0.0.0') OR src_ip > toIPv4('10.255.255.255'))
		  AND (src_ip < toIPv4('172.16.0.0') OR src_ip > toIPv4('172.31.255.255'))
		  AND (src_ip < toIPv4('192.168.0.0') OR src_ip > toIPv4('192.168.255.255'))
		  AND (src_ip < toIPv4('127.0.0.0') OR src_ip > toIPv4('127.255.255.255'))
		  AND (src_ip < toIPv4('178.18.1.0') OR src_ip > toIPv4('178.18.1.255'))
		  AND src_ip != toIPv4('83.194.220.184')
		  AND log_type IN ('WAF', 'IPS', 'ATP', 'Anti-Virus', 'Firewall', 'Threat')
		GROUP BY src_ip
		HAVING attack_count > 0
		ORDER BY blocked_count DESC, attack_count DESC
		LIMIT ?
	`

	rows, err := r.conn.Query(ctx, query, startTime, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query top attackers: %w", err)
	}
	defer rows.Close()

	attackers := []entity.TopAttacker{}
	for rows.Next() {
		var a entity.TopAttacker
		if err := rows.Scan(&a.IP, &a.AttackCount, &a.BlockedCount, &a.UniqueRules, &a.Categories, &a.Country); err != nil {
			return nil, fmt.Errorf("failed to scan attacker: %w", err)
		}
		attackers = append(attackers, a)
	}

	return attackers, nil
}

// GetTopTargets retrieves top targeted hosts
func (r *EventsRepository) GetTopTargets(ctx context.Context, period string, limit int) ([]entity.TopTarget, error) {
	var startTime time.Time
	now := time.Now()

	switch period {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "8h": // v3.57.117: Added 8h period
		startTime = now.Add(-8 * time.Hour)
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
			hostname,
			toInt64(count()) as attack_count,
			toInt64(uniqExact(src_ip)) as unique_ips
		FROM events
		WHERE timestamp >= ? AND hostname != ''
		GROUP BY hostname
		ORDER BY attack_count DESC
		LIMIT ?
	`

	rows, err := r.conn.Query(ctx, query, startTime, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query top targets: %w", err)
	}
	defer rows.Close()

	targets := []entity.TopTarget{}
	for rows.Next() {
		var t entity.TopTarget
		if err := rows.Scan(&t.Hostname, &t.AttackCount, &t.UniqueIPs); err != nil {
			return nil, fmt.Errorf("failed to scan target: %w", err)
		}
		targets = append(targets, t)
	}

	return targets, nil
}

// GetStatsByLogType retrieves stats grouped by log type
// v3.57.114: Exclude infrastructure IP 83.194.220.184
func (r *EventsRepository) GetStatsByLogType(ctx context.Context, period string) (map[string]uint64, error) {
	var startTime time.Time
	now := time.Now()

	switch period {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "8h": // v3.57.117: Added 8h period
		startTime = now.Add(-8 * time.Hour)
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
		SELECT log_type, count() as count
		FROM events
		WHERE timestamp >= ?
			AND src_ip != toIPv4('83.194.220.184')
		GROUP BY log_type
	`

	rows, err := r.conn.Query(ctx, query, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query stats by log type: %w", err)
	}
	defer rows.Close()

	result := make(map[string]uint64)
	for rows.Next() {
		var logType string
		var count uint64
		if err := rows.Scan(&logType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan stat: %w", err)
		}
		result[logType] = count
	}

	return result, nil
}

// GetGeoHeatmap retrieves geographic distribution data
// v3.57.114: Exclude infrastructure IP 83.194.220.184
func (r *EventsRepository) GetGeoHeatmap(ctx context.Context, period string) ([]map[string]interface{}, error) {
	var startTime time.Time
	now := time.Now()

	switch period {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "8h": // v3.57.117: Added 8h period
		startTime = now.Add(-8 * time.Hour)
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
			geo_country,
			count() as count,
			uniqExact(src_ip) as unique_ips
		FROM events
		WHERE timestamp >= ? AND geo_country != ''
			AND src_ip != toIPv4('83.194.220.184')
		GROUP BY geo_country
		ORDER BY count DESC
	`

	rows, err := r.conn.Query(ctx, query, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query geo heatmap: %w", err)
	}
	defer rows.Close()

	result := []map[string]interface{}{}
	for rows.Next() {
		var country string
		var count, uniqueIPs uint64
		if err := rows.Scan(&country, &count, &uniqueIPs); err != nil {
			return nil, fmt.Errorf("failed to scan geo data: %w", err)
		}
		result = append(result, map[string]interface{}{
			"country":    country,
			"count":      count,
			"unique_ips": uniqueIPs,
		})
	}

	return result, nil
}

// GetGeoHeatmapFiltered retrieves geographic distribution filtered by attack types
// attackTypes can include: waf, ips, malware, bruteforce, ddos, threat
func (r *EventsRepository) GetGeoHeatmapFiltered(ctx context.Context, period string, attackTypes []string) ([]map[string]interface{}, error) {
	var startTime time.Time
	now := time.Now()

	switch period {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "8h": // v3.57.117: Added 8h period
		startTime = now.Add(-8 * time.Hour)
	case "24h":
		startTime = now.Add(-24 * time.Hour)
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		startTime = now.Add(-24 * time.Hour)
	}

	// Build attack type filter conditions
	var conditions []string
	for _, at := range attackTypes {
		switch at {
		case "waf":
			conditions = append(conditions, "log_type = 'WAF'")
		case "ips":
			conditions = append(conditions, "(log_type = 'IPS' OR category LIKE '%IDS%' OR category LIKE '%IPS%')")
		case "malware":
			conditions = append(conditions, "(log_type = 'Anti-Virus' OR category LIKE '%Malware%')")
		case "bruteforce":
			conditions = append(conditions, "(category LIKE '%Brute%' OR category LIKE '%Auth Failure%')")
		case "ddos":
			conditions = append(conditions, "(category LIKE '%DDoS%' OR category LIKE '%Flood%' OR category LIKE '%DoS%')")
		case "threat":
			conditions = append(conditions, "(log_type = 'Threat' OR category LIKE '%Threat%' OR category LIKE '%C2%' OR category LIKE '%Botnet%')")
		}
	}

	// Build WHERE clause for attack types
	var whereClause string
	if len(conditions) > 0 {
		whereClause = "AND (" + strings.Join(conditions, " OR ") + ")"
	} else {
		// By default (no filters), show all security attack types combined
		// WAF + IPS + Anti-Virus + Threat (excludes Firewall, Unknown, Admin, etc.)
		whereClause = "AND (log_type = 'WAF' OR log_type = 'IPS' OR log_type = 'Anti-Virus' OR log_type = 'Threat' OR category LIKE '%Malware%' OR category LIKE '%IDS%' OR category LIKE '%IPS%' OR category LIKE '%Threat%' OR category LIKE '%C2%' OR category LIKE '%Botnet%')"
	}

	// v3.57.112: Filter out XGS public IP 83.194.220.184 from attack map
	// v3.57.113: Filter out 178.18.1.0/24 internal management network
	query := fmt.Sprintf(`
		SELECT
			geo_country,
			count() as count,
			uniqExact(src_ip) as unique_ips
		FROM events
		WHERE timestamp >= ? AND geo_country != ''
			AND src_ip != toIPv4('83.194.220.184')
			AND (src_ip < toIPv4('178.18.1.0') OR src_ip > toIPv4('178.18.1.255'))
			%s
		GROUP BY geo_country
		ORDER BY count DESC
	`, whereClause)

	rows, err := r.conn.Query(ctx, query, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query geo heatmap filtered: %w", err)
	}
	defer rows.Close()

	result := []map[string]interface{}{}
	for rows.Next() {
		var country string
		var count, uniqueIPs uint64
		if err := rows.Scan(&country, &count, &uniqueIPs); err != nil {
			return nil, fmt.Errorf("failed to scan geo data: %w", err)
		}
		result = append(result, map[string]interface{}{
			"country":    country,
			"count":      count,
			"unique_ips": uniqueIPs,
		})
	}

	return result, nil
}

// GetGeoHeatmapFilteredRange retrieves geographic distribution for explicit time range (v3.53.105)
// Used for custom date selection in Attack Map
func (r *EventsRepository) GetGeoHeatmapFilteredRange(ctx context.Context, startTime, endTime time.Time, attackTypes []string) ([]map[string]interface{}, error) {
	// Build attack type filter conditions (same as GetGeoHeatmapFiltered)
	var conditions []string
	for _, at := range attackTypes {
		switch at {
		case "waf":
			conditions = append(conditions, "log_type = 'WAF'")
		case "ips":
			conditions = append(conditions, "(log_type = 'IPS' OR category LIKE '%IDS%' OR category LIKE '%IPS%')")
		case "malware":
			conditions = append(conditions, "(log_type = 'Anti-Virus' OR category LIKE '%Malware%')")
		case "bruteforce":
			conditions = append(conditions, "(category LIKE '%Brute%' OR category LIKE '%Auth Failure%')")
		case "ddos":
			conditions = append(conditions, "(category LIKE '%DDoS%' OR category LIKE '%Flood%' OR category LIKE '%DoS%')")
		case "threat":
			conditions = append(conditions, "(log_type = 'Threat' OR category LIKE '%Threat%' OR category LIKE '%C2%' OR category LIKE '%Botnet%')")
		}
	}

	// Build WHERE clause for attack types
	var whereClause string
	if len(conditions) > 0 {
		whereClause = "AND (" + strings.Join(conditions, " OR ") + ")"
	} else {
		// By default (no filters), show all security attack types combined
		whereClause = "AND (log_type = 'WAF' OR log_type = 'IPS' OR log_type = 'Anti-Virus' OR log_type = 'Threat' OR category LIKE '%Malware%' OR category LIKE '%IDS%' OR category LIKE '%IPS%' OR category LIKE '%Threat%' OR category LIKE '%C2%' OR category LIKE '%Botnet%')"
	}

	// v3.57.112: Filter out XGS public IP 83.194.220.184 from attack map
	// v3.57.113: Filter out 178.18.1.0/24 internal management network
	query := fmt.Sprintf(`
		SELECT
			geo_country,
			count() as count,
			uniqExact(src_ip) as unique_ips
		FROM events
		WHERE timestamp >= ? AND timestamp <= ? AND geo_country != ''
			AND src_ip != toIPv4('83.194.220.184')
			AND (src_ip < toIPv4('178.18.1.0') OR src_ip > toIPv4('178.18.1.255'))
			%s
		GROUP BY geo_country
		ORDER BY count DESC
	`, whereClause)

	rows, err := r.conn.Query(ctx, query, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query geo heatmap filtered range: %w", err)
	}
	defer rows.Close()

	result := []map[string]interface{}{}
	for rows.Next() {
		var country string
		var count, uniqueIPs uint64
		if err := rows.Scan(&country, &count, &uniqueIPs); err != nil {
			return nil, fmt.Errorf("failed to scan geo data: %w", err)
		}
		result = append(result, map[string]interface{}{
			"country":    country,
			"count":      count,
			"unique_ips": uniqueIPs,
		})
	}

	return result, nil
}

// GetUniqueHostnames returns unique hostnames for a given log type
func (r *EventsRepository) GetUniqueHostnames(ctx context.Context, logType string) ([]string, error) {
	query := `
		SELECT DISTINCT hostname
		FROM events
		WHERE log_type = ? AND hostname != '' AND hostname != 'Unknown' AND hostname != 'Unknown (Direct IP)'
		ORDER BY hostname
	`

	rows, err := r.conn.Query(ctx, query, logType)
	if err != nil {
		return nil, fmt.Errorf("failed to query unique hostnames: %w", err)
	}
	defer rows.Close()

	hostnames := []string{}
	for rows.Next() {
		var hostname string
		if err := rows.Scan(&hostname); err != nil {
			return nil, fmt.Errorf("failed to scan hostname: %w", err)
		}
		hostnames = append(hostnames, hostname)
	}

	return hostnames, nil
}

// RawQuery executes a raw SQL query and returns rows
func (r *EventsRepository) RawQuery(ctx context.Context, query string, args ...interface{}) (Rows, error) {
	return r.conn.Query(ctx, query, args...)
}

// Rows interface for query results
type Rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Close() error
}

// GetSyslogStatus returns the current syslog ingestion status
func (r *EventsRepository) GetSyslogStatus(ctx context.Context) (*entity.SyslogStatus, error) {
	query := `
		SELECT
			max(timestamp) as last_event,
			countIf(timestamp >= now() - INTERVAL 1 HOUR) as events_last_hour
		FROM events
	`

	var lastEvent time.Time
	var eventsLastHour uint64

	if err := r.conn.QueryRow(ctx, query).Scan(&lastEvent, &eventsLastHour); err != nil {
		return nil, fmt.Errorf("failed to get syslog status: %w", err)
	}

	now := time.Now()
	secondsSinceLast := int64(now.Sub(lastEvent).Seconds())

	// Consider "receiving" if we got an event in the last 5 minutes
	isReceiving := secondsSinceLast < 300

	return &entity.SyslogStatus{
		LastEventTime:    lastEvent,
		EventsLastHour:   eventsLastHour,
		IsReceiving:      isReceiving,
		SecondsSinceLast: secondsSinceLast,
	}, nil
}

// GetCriticalAlerts returns recent critical and high severity alerts
// v3.57.101: Now queries modsec_logs for WAF critical alerts (CRITICAL/WARNING severity)
func (r *EventsRepository) GetCriticalAlerts(ctx context.Context, limit int, period string) ([]entity.CriticalAlert, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	// Calculate start time from period
	var startTime time.Time
	now := time.Now()

	switch period {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "8h": // v3.57.117: Added 8h period
		startTime = now.Add(-8 * time.Hour)
	case "24h":
		startTime = now.Add(-24 * time.Hour)
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		startTime = now.Add(-24 * time.Hour)
	}

	alerts := []entity.CriticalAlert{}

	// v3.57.101: Query modsec_logs for WAF critical alerts (where real severity data lives)
	modsecQuery := `
		SELECT
			toString(id) as event_id,
			timestamp,
			'WAF' as log_type,
			attack_type as category,
			CASE
				WHEN rule_severity = 'CRITICAL' THEN 'critical'
				WHEN rule_severity = 'WARNING' OR rule_severity = 'ERROR' THEN 'high'
				ELSE 'medium'
			END as severity,
			IPv4NumToString(src_ip) as src_ip,
			'' as dst_ip,
			hostname,
			rule_id,
			rule_msg as rule_name,
			rule_data as message,
			CASE WHEN is_blocking = 1 THEN 'blocked' ELSE 'detected' END as action,
			'' as geo_country
		FROM modsec_logs
		WHERE rule_severity IN ('CRITICAL', 'WARNING', 'ERROR')
		AND timestamp >= ?
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := r.conn.Query(ctx, modsecQuery, startTime, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query modsec critical alerts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var a entity.CriticalAlert
		if err := rows.Scan(
			&a.EventID, &a.Timestamp, &a.LogType, &a.Category, &a.Severity,
			&a.SrcIP, &a.DstIP, &a.Hostname, &a.RuleID, &a.RuleName,
			&a.Message, &a.Action, &a.Country,
		); err != nil {
			return nil, fmt.Errorf("failed to scan modsec alert: %w", err)
		}
		alerts = append(alerts, a)
	}

	// Also check events table for any properly-tagged alerts (IPS, ATP, etc.)
	eventsQuery := `
		SELECT
			toString(event_id) as event_id,
			timestamp,
			log_type,
			category,
			severity,
			IPv4NumToString(src_ip) as src_ip,
			IPv4NumToString(dst_ip) as dst_ip,
			hostname,
			rule_id,
			rule_name,
			message,
			action,
			geo_country
		FROM events
		WHERE severity IN ('critical', 'high')
		AND timestamp >= ?
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows2, err := r.conn.Query(ctx, eventsQuery, startTime, limit)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var a entity.CriticalAlert
			if err := rows2.Scan(
				&a.EventID, &a.Timestamp, &a.LogType, &a.Category, &a.Severity,
				&a.SrcIP, &a.DstIP, &a.Hostname, &a.RuleID, &a.RuleName,
				&a.Message, &a.Action, &a.Country,
			); err == nil {
				alerts = append(alerts, a)
			}
		}
	}

	// Sort by timestamp descending and limit
	// (already sorted from queries, just ensure limit)
	if len(alerts) > limit {
		alerts = alerts[:limit]
	}

	return alerts, nil
}

// GetZoneTraffic returns traffic flow between network zones
func (r *EventsRepository) GetZoneTraffic(ctx context.Context, period string, limit int) (*entity.ZoneTrafficStats, error) {
	var startTime time.Time
	now := time.Now()

	switch period {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "8h": // v3.57.117: Added 8h period
		startTime = now.Add(-8 * time.Hour)
	case "24h":
		startTime = now.Add(-24 * time.Hour)
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		startTime = now.Add(-24 * time.Hour)
	}

	if limit <= 0 || limit > 50 {
		limit = 20
	}

	// First check if src_zone column exists (migration 006 may not be applied)
	checkQuery := `SELECT count() FROM system.columns WHERE database = 'vigilance_x' AND table = 'events' AND name = 'src_zone'`
	var columnExists uint64
	if err := r.conn.QueryRow(ctx, checkQuery).Scan(&columnExists); err != nil || columnExists == 0 {
		// Column doesn't exist - return empty stats instead of error
		return &entity.ZoneTrafficStats{
			Flows:       []entity.ZoneTraffic{},
			TotalFlows:  0,
			UniqueZones: []string{},
		}, nil
	}

	// Query zone traffic flows
	query := `
		SELECT
			src_zone,
			dst_zone,
			count() as event_count,
			countIf(action = 'drop') as blocked_count,
			countIf(action IN ('allow', 'accept')) as allowed_count,
			uniqExact(src_ip) as unique_ips,
			countIf(severity = 'critical') as critical_count,
			countIf(severity = 'high') as high_count
		FROM events
		WHERE timestamp >= ?
		  AND src_zone != ''
		  AND dst_zone != ''
		GROUP BY src_zone, dst_zone
		ORDER BY event_count DESC
		LIMIT ?
	`

	rows, err := r.conn.Query(ctx, query, startTime, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query zone traffic: %w", err)
	}
	defer rows.Close()

	flows := []entity.ZoneTraffic{}
	for rows.Next() {
		var f entity.ZoneTraffic
		if err := rows.Scan(
			&f.SrcZone, &f.DstZone, &f.EventCount, &f.BlockedCount,
			&f.AllowedCount, &f.UniqueIPs, &f.CriticalCount, &f.HighCount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan zone traffic: %w", err)
		}
		if f.EventCount > 0 {
			f.BlockRate = float64(f.BlockedCount) / float64(f.EventCount) * 100
		}
		flows = append(flows, f)
	}

	// Get unique zones
	zonesQuery := `
		SELECT DISTINCT zone FROM (
			SELECT src_zone as zone FROM events WHERE timestamp >= ? AND src_zone != ''
			UNION ALL
			SELECT dst_zone as zone FROM events WHERE timestamp >= ? AND dst_zone != ''
		)
		ORDER BY zone
	`

	zoneRows, err := r.conn.Query(ctx, zonesQuery, startTime, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query unique zones: %w", err)
	}
	defer zoneRows.Close()

	zones := []string{}
	for zoneRows.Next() {
		var zone string
		if err := zoneRows.Scan(&zone); err != nil {
			return nil, fmt.Errorf("failed to scan zone: %w", err)
		}
		zones = append(zones, zone)
	}

	return &entity.ZoneTrafficStats{
		Flows:       flows,
		TotalFlows:  uint64(len(flows)),
		UniqueZones: zones,
	}, nil
}

// EventNeedingGeo represents an event that needs geo enrichment
type EventNeedingGeo struct {
	EventID   string
	SrcIP     string
	Timestamp time.Time
}

// GetEventsNeedingGeoEnrichment returns events with valid public IPs but no geo_country
func (r *EventsRepository) GetEventsNeedingGeoEnrichment(ctx context.Context, limit int) ([]EventNeedingGeo, error) {
	if limit <= 0 {
		limit = 1000
	}

	// Get events with valid public IPs (not 0.0.0.0, not private ranges) and empty geo_country
	// Note: Alias must be different from column name to avoid shadowing in WHERE clause
	query := `
		SELECT
			toString(event_id) as event_id,
			IPv4NumToString(src_ip) as ip_str,
			timestamp
		FROM events
		WHERE geo_country = ''
		  AND src_ip != toIPv4('0.0.0.0')
		  AND (src_ip < toIPv4('10.0.0.0') OR src_ip > toIPv4('10.255.255.255'))
		  AND (src_ip < toIPv4('172.16.0.0') OR src_ip > toIPv4('172.31.255.255'))
		  AND (src_ip < toIPv4('192.168.0.0') OR src_ip > toIPv4('192.168.255.255'))
		  AND (src_ip < toIPv4('127.0.0.0') OR src_ip > toIPv4('127.255.255.255'))
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := r.conn.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query events needing geo: %w", err)
	}
	defer rows.Close()

	events := []EventNeedingGeo{}
	for rows.Next() {
		var e EventNeedingGeo
		if err := rows.Scan(&e.EventID, &e.SrcIP, &e.Timestamp); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, e)
	}

	return events, nil
}

// UpdateEventGeo updates the geo_country for an event
func (r *EventsRepository) UpdateEventGeo(ctx context.Context, srcIP string, countryCode string) error {
	// Use ALTER TABLE UPDATE mutation for MergeTree
	query := `
		ALTER TABLE events
		UPDATE geo_country = ?
		WHERE src_ip = toIPv4(?) AND geo_country = ''
	`

	if err := r.conn.Exec(ctx, query, countryCode, srcIP); err != nil {
		return fmt.Errorf("failed to update event geo: %w", err)
	}

	return nil
}

// UpdateEventsGeoBatch updates geo_country for multiple IPs at once
func (r *EventsRepository) UpdateEventsGeoBatch(ctx context.Context, ipToCountry map[string]string) error {
	for ip, country := range ipToCountry {
		if err := r.UpdateEventGeo(ctx, ip, country); err != nil {
			r.logger.Warn("Failed to update geo for IP", "ip", ip, "error", err)
			continue
		}
	}
	return nil
}

// GetUniqueIPsNeedingGeo returns unique IPs that need geo enrichment
func (r *EventsRepository) GetUniqueIPsNeedingGeo(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 100
	}

	// Note: Alias must be different from column name to avoid shadowing in WHERE clause
	query := `
		SELECT DISTINCT IPv4NumToString(src_ip) as ip_str
		FROM events
		WHERE geo_country = ''
		  AND src_ip != toIPv4('0.0.0.0')
		  AND (src_ip < toIPv4('10.0.0.0') OR src_ip > toIPv4('10.255.255.255'))
		  AND (src_ip < toIPv4('172.16.0.0') OR src_ip > toIPv4('172.31.255.255'))
		  AND (src_ip < toIPv4('192.168.0.0') OR src_ip > toIPv4('192.168.255.255'))
		  AND (src_ip < toIPv4('127.0.0.0') OR src_ip > toIPv4('127.255.255.255'))
		LIMIT ?
	`

	rows, err := r.conn.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query unique IPs: %w", err)
	}
	defer rows.Close()

	ips := []string{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("failed to scan IP: %w", err)
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// GetRecentWAFBlockEvents returns the count of WAF blocking events since the given time
// This is used by the WAF watcher to detect new attacks and trigger ModSec sync
func (r *EventsRepository) GetRecentWAFBlockEvents(ctx context.Context, since time.Time) (int, error) {
	// Query for WAF events with blocking actions since the given timestamp
	// Actions: 'drop', 'blocked', 'Block', 'Drop', etc.
	query := `
		SELECT count() as cnt
		FROM events
		WHERE timestamp > ?
		  AND log_type = 'WAF'
		  AND (
			  lower(action) IN ('drop', 'blocked', 'deny', 'reject', 'block')
			  OR lower(category) LIKE '%blocked%'
			  OR lower(category) LIKE '%denied%'
		  )
	`

	var count uint64
	if err := r.conn.QueryRow(ctx, query, since).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count WAF block events: %w", err)
	}

	return int(count), nil
}

// FalsePositivePattern represents a potential false positive detection pattern
// v3.57.118: Used for detecting repeated identical attacks (same rule_id + same URI)
type FalsePositivePattern struct {
	IP         string
	RuleID     string
	URI        string
	Hostname   string
	MatchCount uint64
	FirstEvent time.Time
	LastEvent  time.Time
}

// DetectFalsePositivePattern checks if an IP has potential false positive patterns
// v3.57.118: An FP is detected when same IP triggers 10+ identical attacks (same rule_id + same URI)
// This typically indicates a misconfigured application or overly strict ModSec rules
func (r *EventsRepository) DetectFalsePositivePattern(ctx context.Context, ip string, threshold int) (*FalsePositivePattern, error) {
	if threshold <= 0 {
		threshold = 10 // Default threshold
	}

	// Query to find repeated patterns (same rule_id + same URL) for this IP
	// Look at both events table and modsec_logs table
	query := `
		SELECT
			rule_id,
			url,
			anyLast(hostname) as hostname,
			count() as match_count,
			min(timestamp) as first_event,
			max(timestamp) as last_event
		FROM events
		WHERE src_ip = toIPv4(?)
		  AND log_type = 'WAF'
		  AND rule_id != ''
		  AND url != ''
		  AND timestamp >= now() - INTERVAL 24 HOUR
		GROUP BY rule_id, url
		HAVING match_count >= ?
		ORDER BY match_count DESC
		LIMIT 1
	`

	var pattern FalsePositivePattern
	pattern.IP = ip

	row := r.conn.QueryRow(ctx, query, ip, threshold)
	err := row.Scan(
		&pattern.RuleID,
		&pattern.URI,
		&pattern.Hostname,
		&pattern.MatchCount,
		&pattern.FirstEvent,
		&pattern.LastEvent,
	)

	if err != nil {
		// Also check modsec_logs table for more detailed WAF data
		modsecQuery := `
			SELECT
				rule_id,
				uri,
				anyLast(hostname) as hostname,
				count() as match_count,
				min(timestamp) as first_event,
				max(timestamp) as last_event
			FROM modsec_logs
			WHERE src_ip = toIPv4(?)
			  AND rule_id != ''
			  AND uri != ''
			  AND timestamp >= now() - INTERVAL 24 HOUR
			GROUP BY rule_id, uri
			HAVING match_count >= ?
			ORDER BY match_count DESC
			LIMIT 1
		`

		row := r.conn.QueryRow(ctx, modsecQuery, ip, threshold)
		err = row.Scan(
			&pattern.RuleID,
			&pattern.URI,
			&pattern.Hostname,
			&pattern.MatchCount,
			&pattern.FirstEvent,
			&pattern.LastEvent,
		)

		if err != nil {
			// No FP pattern found
			return nil, nil
		}
	}

	return &pattern, nil
}
