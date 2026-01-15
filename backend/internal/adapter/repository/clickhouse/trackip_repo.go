package clickhouse

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// TrackIPRepository handles IP/hostname tracking queries across all log tables
type TrackIPRepository struct {
	conn clickhouse.Conn
}

// NewTrackIPRepository creates a new TrackIPRepository
func NewTrackIPRepository(conn clickhouse.Conn) *TrackIPRepository {
	return &TrackIPRepository{conn: conn}
}

// SearchEvents searches the main events table (WAF, IPS, ATP, etc.)
func (r *TrackIPRepository) SearchEvents(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPWAFEvent, int64, error) {
	conditions := []string{"1=1"}
	args := []interface{}{}

	// Build WHERE clause based on query type
	// CRITICAL: Use table prefix to avoid ClickHouse alias collision (v3.55.101 fix)
	if query.QueryType == "ip" {
		conditions = append(conditions, "(e.src_ip = toIPv4(?) OR e.dst_ip = toIPv4(?))")
		args = append(args, query.Query, query.Query)
	} else {
		// Hostname search - search in hostname and url fields
		conditions = append(conditions, "(e.hostname = ? OR e.hostname LIKE ?)")
		args = append(args, query.Query, "%"+query.Query+"%")
	}

	// Time range
	if query.StartTime != nil {
		conditions = append(conditions, "e.timestamp >= ?")
		args = append(args, *query.StartTime)
	}
	if query.EndTime != nil {
		conditions = append(conditions, "e.timestamp <= ?")
		args = append(args, *query.EndTime)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countSQL := fmt.Sprintf(`
		SELECT count()
		FROM vigilance_x.events e
		WHERE %s
	`, whereClause)

	var total uint64
	if err := r.conn.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count events: %w", err)
	}

	if total == 0 {
		return []entity.TrackIPWAFEvent{}, 0, nil
	}

	// Data query with limit
	dataSQL := fmt.Sprintf(`
		SELECT
			e.event_id,
			e.timestamp,
			e.log_type,
			e.category,
			e.severity,
			IPv4NumToString(e.src_ip) as src_ip,
			IPv4NumToString(e.dst_ip) as dst_ip,
			e.src_port,
			e.dst_port,
			e.protocol,
			e.hostname,
			e.url,
			e.rule_id,
			e.rule_name,
			e.action,
			e.message
		FROM vigilance_x.events e
		WHERE %s
		ORDER BY e.timestamp DESC
		LIMIT ?
	`, whereClause)

	args = append(args, query.Limit)
	rows, err := r.conn.Query(ctx, dataSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	events := make([]entity.TrackIPWAFEvent, 0)
	for rows.Next() {
		var ev entity.TrackIPWAFEvent
		if err := rows.Scan(
			&ev.EventID, &ev.Timestamp, &ev.LogType, &ev.Category, &ev.Severity,
			&ev.SrcIP, &ev.DstIP, &ev.SrcPort, &ev.DstPort, &ev.Protocol,
			&ev.Hostname, &ev.URL, &ev.RuleID, &ev.RuleName, &ev.Action, &ev.Message,
		); err != nil {
			return nil, 0, fmt.Errorf("scan event: %w", err)
		}
		events = append(events, ev)
	}

	return events, int64(total), nil
}

// SearchModSec searches the modsec_logs table
func (r *TrackIPRepository) SearchModSec(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPModSecEvent, int64, error) {
	conditions := []string{"1=1"}
	args := []interface{}{}

	if query.QueryType == "ip" {
		conditions = append(conditions, "m.src_ip = toIPv4(?)")
		args = append(args, query.Query)
	} else {
		conditions = append(conditions, "(m.hostname = ? OR m.hostname LIKE ?)")
		args = append(args, query.Query, "%"+query.Query+"%")
	}

	if query.StartTime != nil {
		conditions = append(conditions, "m.timestamp >= ?")
		args = append(args, *query.StartTime)
	}
	if query.EndTime != nil {
		conditions = append(conditions, "m.timestamp <= ?")
		args = append(args, *query.EndTime)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count
	countSQL := fmt.Sprintf(`
		SELECT count()
		FROM vigilance_x.modsec_logs m
		WHERE %s
	`, whereClause)

	var total uint64
	if err := r.conn.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count modsec: %w", err)
	}

	if total == 0 {
		return []entity.TrackIPModSecEvent{}, 0, nil
	}

	// Data
	dataSQL := fmt.Sprintf(`
		SELECT
			m.id,
			m.timestamp,
			m.unique_id,
			IPv4NumToString(m.src_ip) as src_ip,
			m.hostname,
			m.uri,
			m.rule_id,
			m.rule_msg,
			m.attack_type,
			m.total_score,
			m.is_blocking
		FROM vigilance_x.modsec_logs m
		WHERE %s
		ORDER BY m.timestamp DESC
		LIMIT ?
	`, whereClause)

	args = append(args, query.Limit)
	rows, err := r.conn.Query(ctx, dataSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query modsec: %w", err)
	}
	defer rows.Close()

	events := make([]entity.TrackIPModSecEvent, 0)
	for rows.Next() {
		var ev entity.TrackIPModSecEvent
		var isBlocking uint8
		if err := rows.Scan(
			&ev.ID, &ev.Timestamp, &ev.UniqueID, &ev.SrcIP, &ev.Hostname,
			&ev.URI, &ev.RuleID, &ev.RuleMsg, &ev.AttackType,
			&ev.TotalScore, &isBlocking,
		); err != nil {
			return nil, 0, fmt.Errorf("scan modsec: %w", err)
		}
		ev.IsBlocking = isBlocking == 1
		events = append(events, ev)
	}

	return events, int64(total), nil
}

// SearchFirewall searches the firewall_events table
func (r *TrackIPRepository) SearchFirewall(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPFirewallEvent, int64, error) {
	// Firewall events don't have hostname field, skip for hostname queries
	if query.QueryType != "ip" {
		return []entity.TrackIPFirewallEvent{}, 0, nil
	}

	conditions := []string{"1=1"}
	args := []interface{}{}

	// Search in both src_ip and dst_ip
	conditions = append(conditions, "(f.src_ip = toIPv4(?) OR f.dst_ip = toIPv4(?))")
	args = append(args, query.Query, query.Query)

	if query.StartTime != nil {
		conditions = append(conditions, "f.timestamp >= ?")
		args = append(args, *query.StartTime)
	}
	if query.EndTime != nil {
		conditions = append(conditions, "f.timestamp <= ?")
		args = append(args, *query.EndTime)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count
	countSQL := fmt.Sprintf(`
		SELECT count()
		FROM vigilance_x.firewall_events f
		WHERE %s
	`, whereClause)

	var total uint64
	if err := r.conn.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count firewall: %w", err)
	}

	if total == 0 {
		return []entity.TrackIPFirewallEvent{}, 0, nil
	}

	// Data
	dataSQL := fmt.Sprintf(`
		SELECT
			f.event_id,
			f.timestamp,
			f.rule_name,
			IPv4NumToString(f.src_ip) as src_ip,
			IPv4NumToString(f.dst_ip) as dst_ip,
			f.src_port,
			f.dst_port,
			f.protocol,
			f.action,
			f.src_zone,
			f.dst_zone,
			f.bytes,
			f.application
		FROM vigilance_x.firewall_events f
		WHERE %s
		ORDER BY f.timestamp DESC
		LIMIT ?
	`, whereClause)

	args = append(args, query.Limit)
	rows, err := r.conn.Query(ctx, dataSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query firewall: %w", err)
	}
	defer rows.Close()

	events := make([]entity.TrackIPFirewallEvent, 0)
	for rows.Next() {
		var ev entity.TrackIPFirewallEvent
		if err := rows.Scan(
			&ev.EventID, &ev.Timestamp, &ev.RuleName,
			&ev.SrcIP, &ev.DstIP, &ev.SrcPort, &ev.DstPort,
			&ev.Protocol, &ev.Action, &ev.SrcZone, &ev.DstZone,
			&ev.Bytes, &ev.Application,
		); err != nil {
			return nil, 0, fmt.Errorf("scan firewall: %w", err)
		}
		events = append(events, ev)
	}

	return events, int64(total), nil
}

// SearchVPN searches the vpn_events table
func (r *TrackIPRepository) SearchVPN(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPVPNEvent, int64, error) {
	conditions := []string{"1=1"}
	args := []interface{}{}

	if query.QueryType == "ip" {
		// VPN events can match on src_ip or assigned_ip
		conditions = append(conditions, "(v.src_ip = toIPv4(?) OR (v.assigned_ip IS NOT NULL AND v.assigned_ip = toIPv4(?)))")
		args = append(args, query.Query, query.Query)
	} else {
		// Search by username for hostname queries
		conditions = append(conditions, "v.user_name = ?")
		args = append(args, query.Query)
	}

	if query.StartTime != nil {
		conditions = append(conditions, "v.timestamp >= ?")
		args = append(args, *query.StartTime)
	}
	if query.EndTime != nil {
		conditions = append(conditions, "v.timestamp <= ?")
		args = append(args, *query.EndTime)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count
	countSQL := fmt.Sprintf(`
		SELECT count()
		FROM vigilance_x.vpn_events v
		WHERE %s
	`, whereClause)

	var total uint64
	if err := r.conn.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count vpn: %w", err)
	}

	if total == 0 {
		return []entity.TrackIPVPNEvent{}, 0, nil
	}

	// Data
	dataSQL := fmt.Sprintf(`
		SELECT
			v.event_id,
			v.timestamp,
			v.event_type,
			v.vpn_type,
			v.user_name,
			IPv4NumToString(v.src_ip) as src_ip,
			if(v.assigned_ip IS NULL, '', IPv4NumToString(v.assigned_ip)) as assigned_ip,
			v.duration_seconds,
			v.bytes_in,
			v.bytes_out,
			v.geo_country
		FROM vigilance_x.vpn_events v
		WHERE %s
		ORDER BY v.timestamp DESC
		LIMIT ?
	`, whereClause)

	args = append(args, query.Limit)
	rows, err := r.conn.Query(ctx, dataSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query vpn: %w", err)
	}
	defer rows.Close()

	events := make([]entity.TrackIPVPNEvent, 0)
	for rows.Next() {
		var ev entity.TrackIPVPNEvent
		if err := rows.Scan(
			&ev.EventID, &ev.Timestamp, &ev.EventType, &ev.VPNType, &ev.UserName,
			&ev.SrcIP, &ev.AssignedIP, &ev.Duration, &ev.BytesIn, &ev.BytesOut,
			&ev.GeoCountry,
		); err != nil {
			return nil, 0, fmt.Errorf("scan vpn: %w", err)
		}
		events = append(events, ev)
	}

	return events, int64(total), nil
}

// SearchATP searches the atp_events table
func (r *TrackIPRepository) SearchATP(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPATPEvent, int64, error) {
	// ATP events don't have hostname field
	if query.QueryType != "ip" {
		return []entity.TrackIPATPEvent{}, 0, nil
	}

	conditions := []string{"1=1"}
	args := []interface{}{}

	conditions = append(conditions, "(a.src_ip = toIPv4(?) OR a.dst_ip = toIPv4(?))")
	args = append(args, query.Query, query.Query)

	if query.StartTime != nil {
		conditions = append(conditions, "a.timestamp >= ?")
		args = append(args, *query.StartTime)
	}
	if query.EndTime != nil {
		conditions = append(conditions, "a.timestamp <= ?")
		args = append(args, *query.EndTime)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count
	countSQL := fmt.Sprintf(`
		SELECT count()
		FROM vigilance_x.atp_events a
		WHERE %s
	`, whereClause)

	var total uint64
	if err := r.conn.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count atp: %w", err)
	}

	if total == 0 {
		return []entity.TrackIPATPEvent{}, 0, nil
	}

	// Data
	dataSQL := fmt.Sprintf(`
		SELECT
			a.event_id,
			a.timestamp,
			IPv4NumToString(a.src_ip) as src_ip,
			IPv4NumToString(a.dst_ip) as dst_ip,
			a.threat_name,
			a.threat_type,
			a.severity,
			a.action,
			a.url,
			a.user_name
		FROM vigilance_x.atp_events a
		WHERE %s
		ORDER BY a.timestamp DESC
		LIMIT ?
	`, whereClause)

	args = append(args, query.Limit)
	rows, err := r.conn.Query(ctx, dataSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query atp: %w", err)
	}
	defer rows.Close()

	events := make([]entity.TrackIPATPEvent, 0)
	for rows.Next() {
		var ev entity.TrackIPATPEvent
		if err := rows.Scan(
			&ev.EventID, &ev.Timestamp, &ev.SrcIP, &ev.DstIP,
			&ev.ThreatName, &ev.ThreatType, &ev.Severity, &ev.Action,
			&ev.URL, &ev.UserName,
		); err != nil {
			return nil, 0, fmt.Errorf("scan atp: %w", err)
		}
		events = append(events, ev)
	}

	return events, int64(total), nil
}

// SearchAntivirus searches the antivirus_events table
func (r *TrackIPRepository) SearchAntivirus(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPAntivirusEvent, int64, error) {
	// Antivirus events don't have hostname field
	if query.QueryType != "ip" {
		return []entity.TrackIPAntivirusEvent{}, 0, nil
	}

	conditions := []string{"1=1"}
	args := []interface{}{}

	conditions = append(conditions, "(av.src_ip = toIPv4(?) OR av.dst_ip = toIPv4(?))")
	args = append(args, query.Query, query.Query)

	if query.StartTime != nil {
		conditions = append(conditions, "av.timestamp >= ?")
		args = append(args, *query.StartTime)
	}
	if query.EndTime != nil {
		conditions = append(conditions, "av.timestamp <= ?")
		args = append(args, *query.EndTime)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count
	countSQL := fmt.Sprintf(`
		SELECT count()
		FROM vigilance_x.antivirus_events av
		WHERE %s
	`, whereClause)

	var total uint64
	if err := r.conn.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count antivirus: %w", err)
	}

	if total == 0 {
		return []entity.TrackIPAntivirusEvent{}, 0, nil
	}

	// Data
	dataSQL := fmt.Sprintf(`
		SELECT
			av.event_id,
			av.timestamp,
			IPv4NumToString(av.src_ip) as src_ip,
			IPv4NumToString(av.dst_ip) as dst_ip,
			av.malware_name,
			av.malware_type,
			av.action,
			av.file_name,
			av.file_path
		FROM vigilance_x.antivirus_events av
		WHERE %s
		ORDER BY av.timestamp DESC
		LIMIT ?
	`, whereClause)

	args = append(args, query.Limit)
	rows, err := r.conn.Query(ctx, dataSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query antivirus: %w", err)
	}
	defer rows.Close()

	events := make([]entity.TrackIPAntivirusEvent, 0)
	for rows.Next() {
		var ev entity.TrackIPAntivirusEvent
		if err := rows.Scan(
			&ev.EventID, &ev.Timestamp, &ev.SrcIP, &ev.DstIP,
			&ev.MalwareName, &ev.MalwareType, &ev.Action,
			&ev.FileName, &ev.FilePath,
		); err != nil {
			return nil, 0, fmt.Errorf("scan antivirus: %w", err)
		}
		events = append(events, ev)
	}

	return events, int64(total), nil
}

// SearchHeartbeat searches the heartbeat_events table
func (r *TrackIPRepository) SearchHeartbeat(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPHeartbeatEvent, int64, error) {
	// Heartbeat only supports IP search
	if query.QueryType != "ip" {
		return []entity.TrackIPHeartbeatEvent{}, 0, nil
	}

	conditions := []string{"1=1"}
	args := []interface{}{}

	conditions = append(conditions, "h.endpoint_ip = toIPv4(?)")
	args = append(args, query.Query)

	if query.StartTime != nil {
		conditions = append(conditions, "h.timestamp >= ?")
		args = append(args, *query.StartTime)
	}
	if query.EndTime != nil {
		conditions = append(conditions, "h.timestamp <= ?")
		args = append(args, *query.EndTime)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count
	countSQL := fmt.Sprintf(`
		SELECT count()
		FROM vigilance_x.heartbeat_events h
		WHERE %s
	`, whereClause)

	var total uint64
	if err := r.conn.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count heartbeat: %w", err)
	}

	if total == 0 {
		return []entity.TrackIPHeartbeatEvent{}, 0, nil
	}

	// Data
	dataSQL := fmt.Sprintf(`
		SELECT
			h.event_id,
			h.timestamp,
			h.endpoint_name,
			IPv4NumToString(h.endpoint_ip) as endpoint_ip,
			h.health_status,
			h.os_type
		FROM vigilance_x.heartbeat_events h
		WHERE %s
		ORDER BY h.timestamp DESC
		LIMIT ?
	`, whereClause)

	args = append(args, query.Limit)
	rows, err := r.conn.Query(ctx, dataSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query heartbeat: %w", err)
	}
	defer rows.Close()

	events := make([]entity.TrackIPHeartbeatEvent, 0)
	for rows.Next() {
		var ev entity.TrackIPHeartbeatEvent
		if err := rows.Scan(
			&ev.EventID, &ev.Timestamp, &ev.EndpointName,
			&ev.EndpointIP, &ev.HealthStatus, &ev.OSType,
		); err != nil {
			return nil, 0, fmt.Errorf("scan heartbeat: %w", err)
		}
		events = append(events, ev)
	}

	return events, int64(total), nil
}

// GetSummaryStats returns aggregated statistics for the query
func (r *TrackIPRepository) GetSummaryStats(ctx context.Context, query *entity.TrackIPQuery) (*entity.TrackIPSummary, error) {
	conditions := []string{"1=1"}
	args := []interface{}{}

	if query.QueryType == "ip" {
		conditions = append(conditions, "(e.src_ip = toIPv4(?) OR e.dst_ip = toIPv4(?))")
		args = append(args, query.Query, query.Query)
	} else {
		conditions = append(conditions, "(e.hostname = ? OR e.hostname LIKE ?)")
		args = append(args, query.Query, "%"+query.Query+"%")
	}

	if query.StartTime != nil {
		conditions = append(conditions, "e.timestamp >= ?")
		args = append(args, *query.StartTime)
	}
	if query.EndTime != nil {
		conditions = append(conditions, "e.timestamp <= ?")
		args = append(args, *query.EndTime)
	}

	whereClause := strings.Join(conditions, " AND ")

	sql := fmt.Sprintf(`
		SELECT
			count() as total,
			min(e.timestamp) as first_seen,
			max(e.timestamp) as last_seen,
			groupUniqArray(10)(e.hostname) as hostnames,
			groupUniqArray(10)(IPv4NumToString(e.dst_ip)) as dst_ips,
			topK(5)(e.dst_port) as top_ports,
			countIf(e.severity = 'critical') as critical,
			countIf(e.severity = 'high') as high,
			countIf(e.severity = 'medium') as medium,
			countIf(e.severity = 'low') as low,
			countIf(e.severity = 'info') as info
		FROM vigilance_x.events e
		WHERE %s
	`, whereClause)

	summary := &entity.TrackIPSummary{
		SeverityBreakdown: make(map[string]int64),
		UniqueHostnames:   []string{},
		UniqueDstIPs:      []string{},
		TopPorts:          []uint16{},
	}

	var firstSeen, lastSeen time.Time
	// Use uint64 for scanning ClickHouse UInt64 values
	var totalEvents, critical, high, medium, low, info uint64

	if err := r.conn.QueryRow(ctx, sql, args...).Scan(
		&totalEvents,
		&firstSeen,
		&lastSeen,
		&summary.UniqueHostnames,
		&summary.UniqueDstIPs,
		&summary.TopPorts,
		&critical, &high, &medium, &low, &info,
	); err != nil {
		return nil, fmt.Errorf("summary stats: %w", err)
	}

	// Convert uint64 to int64 for entity
	summary.TotalEvents = int64(totalEvents)

	if !firstSeen.IsZero() {
		summary.FirstSeen = &firstSeen
	}
	if !lastSeen.IsZero() {
		summary.LastSeen = &lastSeen
	}

	summary.SeverityBreakdown["critical"] = int64(critical)
	summary.SeverityBreakdown["high"] = int64(high)
	summary.SeverityBreakdown["medium"] = int64(medium)
	summary.SeverityBreakdown["low"] = int64(low)
	summary.SeverityBreakdown["info"] = int64(info)

	// Filter out empty strings from arrays
	filteredHostnames := make([]string, 0)
	for _, h := range summary.UniqueHostnames {
		if h != "" {
			filteredHostnames = append(filteredHostnames, h)
		}
	}
	summary.UniqueHostnames = filteredHostnames

	filteredIPs := make([]string, 0)
	for _, ip := range summary.UniqueDstIPs {
		if ip != "" && ip != "0.0.0.0" {
			filteredIPs = append(filteredIPs, ip)
		}
	}
	summary.UniqueDstIPs = filteredIPs

	return summary, nil
}

// SearchWAFSophos searches WAF events from Sophos (log_type='WAF' in events table)
func (r *TrackIPRepository) SearchWAFSophos(ctx context.Context, query *entity.TrackIPQuery) ([]entity.TrackIPWAFEvent, int64, error) {
	conditions := []string{"e.log_type = 'WAF'"}
	args := []interface{}{}

	// Build WHERE clause based on query type
	if query.QueryType == "ip" {
		conditions = append(conditions, "(e.src_ip = toIPv4(?) OR e.dst_ip = toIPv4(?))")
		args = append(args, query.Query, query.Query)
	} else {
		conditions = append(conditions, "(e.hostname = ? OR e.hostname LIKE ?)")
		args = append(args, query.Query, "%"+query.Query+"%")
	}

	// Time range
	if query.StartTime != nil {
		conditions = append(conditions, "e.timestamp >= ?")
		args = append(args, *query.StartTime)
	}
	if query.EndTime != nil {
		conditions = append(conditions, "e.timestamp <= ?")
		args = append(args, *query.EndTime)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countSQL := fmt.Sprintf(`
		SELECT count()
		FROM vigilance_x.events e
		WHERE %s
	`, whereClause)

	var total uint64
	if err := r.conn.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count waf sophos: %w", err)
	}

	if total == 0 {
		return []entity.TrackIPWAFEvent{}, 0, nil
	}

	// Data query with limit
	dataSQL := fmt.Sprintf(`
		SELECT
			e.event_id,
			e.timestamp,
			e.log_type,
			e.category,
			e.severity,
			IPv4NumToString(e.src_ip) as src_ip,
			IPv4NumToString(e.dst_ip) as dst_ip,
			e.src_port,
			e.dst_port,
			e.protocol,
			e.hostname,
			e.url,
			e.rule_id,
			e.rule_name,
			e.action,
			e.message
		FROM vigilance_x.events e
		WHERE %s
		ORDER BY e.timestamp DESC
		LIMIT ?
	`, whereClause)

	args = append(args, query.Limit)
	rows, err := r.conn.Query(ctx, dataSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query waf sophos: %w", err)
	}
	defer rows.Close()

	events := make([]entity.TrackIPWAFEvent, 0)
	for rows.Next() {
		var ev entity.TrackIPWAFEvent
		if err := rows.Scan(
			&ev.EventID, &ev.Timestamp, &ev.LogType, &ev.Category, &ev.Severity,
			&ev.SrcIP, &ev.DstIP, &ev.SrcPort, &ev.DstPort, &ev.Protocol,
			&ev.Hostname, &ev.URL, &ev.RuleID, &ev.RuleName, &ev.Action, &ev.Message,
		); err != nil {
			return nil, 0, fmt.Errorf("scan waf sophos: %w", err)
		}
		events = append(events, ev)
	}

	return events, int64(total), nil
}
