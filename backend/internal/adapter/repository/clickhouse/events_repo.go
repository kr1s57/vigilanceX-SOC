package clickhouse

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"vigilancex/internal/entity"
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
func (r *EventsRepository) GetEvents(ctx context.Context, filters entity.EventFilters, limit, offset int) ([]entity.Event, int64, error) {
	// Build WHERE clause
	conditions := []string{"1=1"}
	args := []interface{}{}

	if filters.LogType != "" {
		conditions = append(conditions, "log_type = ?")
		args = append(args, filters.LogType)
	}
	if filters.Category != "" {
		conditions = append(conditions, "category = ?")
		args = append(args, filters.Category)
	}
	if filters.Severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, filters.Severity)
	}
	if filters.SrcIP != "" {
		conditions = append(conditions, "src_ip = toIPv4(?)")
		args = append(args, filters.SrcIP)
	}
	if filters.DstIP != "" {
		conditions = append(conditions, "dst_ip = toIPv4(?)")
		args = append(args, filters.DstIP)
	}
	if filters.Hostname != "" {
		conditions = append(conditions, "hostname = ?")
		args = append(args, filters.Hostname)
	}
	if filters.RuleID != "" {
		conditions = append(conditions, "rule_id = ?")
		args = append(args, filters.RuleID)
	}
	if filters.Action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, filters.Action)
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
		conditions = append(conditions, "(message ILIKE ? OR rule_name ILIKE ? OR url ILIKE ?)")
		searchPattern := "%" + filters.SearchTerm + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Get total count
	countQuery := fmt.Sprintf(`SELECT count() FROM events WHERE %s`, whereClause)
	var total int64
	if err := r.conn.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count events: %w", err)
	}

	// Get events
	query := fmt.Sprintf(`
		SELECT
			event_id, timestamp, log_type, category, sub_category, severity,
			IPv4NumToString(src_ip) as src_ip, IPv4NumToString(dst_ip) as dst_ip,
			src_port, dst_port, protocol, action, rule_id, rule_name,
			hostname, user_name, url, http_method, http_status, user_agent,
			geo_country, geo_city, geo_asn, geo_org, message, sophos_id, ingested_at
		FROM events
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	args = append(args, limit, offset)

	rows, err := r.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []entity.Event
	for rows.Next() {
		var e entity.Event
		if err := rows.Scan(
			&e.EventID, &e.Timestamp, &e.LogType, &e.Category, &e.SubCategory, &e.Severity,
			&e.SrcIP, &e.DstIP, &e.SrcPort, &e.DstPort, &e.Protocol, &e.Action,
			&e.RuleID, &e.RuleName, &e.Hostname, &e.UserName, &e.URL, &e.HTTPMethod,
			&e.HTTPStatus, &e.UserAgent, &e.GeoCountry, &e.GeoCity, &e.GeoASN,
			&e.GeoOrg, &e.Message, &e.SophosID, &e.IngestedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, e)
	}

	return events, total, nil
}

// GetEventByID retrieves a single event by ID
func (r *EventsRepository) GetEventByID(ctx context.Context, eventID uuid.UUID) (*entity.Event, error) {
	query := `
		SELECT
			event_id, timestamp, log_type, category, sub_category, severity,
			IPv4NumToString(src_ip) as src_ip, IPv4NumToString(dst_ip) as dst_ip,
			src_port, dst_port, protocol, action, rule_id, rule_name,
			hostname, user_name, url, http_method, http_status, user_agent,
			geo_country, geo_city, geo_asn, geo_org, message, raw_log, sophos_id, ingested_at
		FROM events
		WHERE event_id = ?
		LIMIT 1
	`

	var e entity.Event
	if err := r.conn.QueryRow(ctx, query, eventID).Scan(
		&e.EventID, &e.Timestamp, &e.LogType, &e.Category, &e.SubCategory, &e.Severity,
		&e.SrcIP, &e.DstIP, &e.SrcPort, &e.DstPort, &e.Protocol, &e.Action,
		&e.RuleID, &e.RuleName, &e.Hostname, &e.UserName, &e.URL, &e.HTTPMethod,
		&e.HTTPStatus, &e.UserAgent, &e.GeoCountry, &e.GeoCity, &e.GeoASN,
		&e.GeoOrg, &e.Message, &e.RawLog, &e.SophosID, &e.IngestedAt,
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

	query := fmt.Sprintf(`
		SELECT
			%s as time_bucket,
			count() as total_events,
			countIf(action = 'drop') as blocked_events,
			uniqExact(src_ip) as unique_ips
		FROM events
		WHERE timestamp >= ?
		GROUP BY time_bucket
		ORDER BY time_bucket ASC
	`, timeFunc)

	rows, err := r.conn.Query(ctx, query, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query timeline: %w", err)
	}
	defer rows.Close()

	var timeline []entity.TimelinePoint
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
func (r *EventsRepository) GetStats(ctx context.Context, period string) (*entity.EventStats, error) {
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
			count() as total_events,
			countIf(action = 'drop') as blocked_events,
			uniqExact(src_ip) as unique_ips,
			countIf(severity = 'critical') as critical_events,
			countIf(severity = 'high') as high_events,
			countIf(severity = 'medium') as medium_events,
			countIf(severity = 'low') as low_events
		FROM events
		WHERE timestamp >= ?
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

	if stats.TotalEvents > 0 {
		stats.BlockRate = float64(stats.BlockedEvents) / float64(stats.TotalEvents) * 100
	}

	return &stats, nil
}

// GetTopAttackers retrieves top attacking IPs
func (r *EventsRepository) GetTopAttackers(ctx context.Context, period string, limit int) ([]entity.TopAttacker, error) {
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
			IPv4NumToString(src_ip) as ip,
			count() as attack_count,
			countIf(action = 'drop') as blocked_count,
			uniqExact(rule_id) as unique_rules,
			groupUniqArray(5)(category) as categories,
			any(geo_country) as country
		FROM events
		WHERE timestamp >= ?
		GROUP BY src_ip
		ORDER BY attack_count DESC
		LIMIT ?
	`

	rows, err := r.conn.Query(ctx, query, startTime, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query top attackers: %w", err)
	}
	defer rows.Close()

	var attackers []entity.TopAttacker
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
			count() as attack_count,
			uniqExact(src_ip) as unique_ips
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

	var targets []entity.TopTarget
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
func (r *EventsRepository) GetStatsByLogType(ctx context.Context, period string) (map[string]int64, error) {
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
		SELECT log_type, count() as count
		FROM events
		WHERE timestamp >= ?
		GROUP BY log_type
	`

	rows, err := r.conn.Query(ctx, query, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query stats by log type: %w", err)
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var logType string
		var count int64
		if err := rows.Scan(&logType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan stat: %w", err)
		}
		result[logType] = count
	}

	return result, nil
}

// GetGeoHeatmap retrieves geographic distribution data
func (r *EventsRepository) GetGeoHeatmap(ctx context.Context, period string) ([]map[string]interface{}, error) {
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
			geo_country,
			count() as count,
			uniqExact(src_ip) as unique_ips
		FROM events
		WHERE timestamp >= ? AND geo_country != ''
		GROUP BY geo_country
		ORDER BY count DESC
	`

	rows, err := r.conn.Query(ctx, query, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query geo heatmap: %w", err)
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var country string
		var count, uniqueIPs int64
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
