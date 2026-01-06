package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/kr1s57/vigilancex/internal/usecase/anomalies"
)

// AnomaliesRepository handles anomaly data persistence in ClickHouse
type AnomaliesRepository struct {
	conn *Connection
}

// NewAnomaliesRepository creates a new anomalies repository
func NewAnomaliesRepository(conn *Connection) *AnomaliesRepository {
	return &AnomaliesRepository{conn: conn}
}

// GetNewIPs finds IPs seen in recent window but not in baseline window
func (r *AnomaliesRepository) GetNewIPs(ctx context.Context, recentWindow, baselineWindow time.Duration) ([]entity.NewIPAnomaly, error) {
	query := `
		SELECT
			src_ip,
			min(timestamp) as first_seen,
			count() as event_count,
			groupArray(DISTINCT log_type) as log_types,
			any(geo_country) as country
		FROM events
		WHERE timestamp >= now() - INTERVAL ? HOUR
		  AND src_ip NOT IN (
			SELECT DISTINCT src_ip
			FROM events
			WHERE timestamp >= now() - INTERVAL ? DAY
			  AND timestamp < now() - INTERVAL ? HOUR
		  )
		GROUP BY src_ip
		HAVING event_count >= 1
		ORDER BY event_count DESC
		LIMIT 100
	`

	recentHours := int(recentWindow.Hours())
	baselineDays := int(baselineWindow.Hours() / 24)

	rows, err := r.conn.DB().Query(ctx, query, recentHours, baselineDays, recentHours)
	if err != nil {
		return nil, fmt.Errorf("query new IPs: %w", err)
	}
	defer rows.Close()

	var results []entity.NewIPAnomaly
	for rows.Next() {
		var anomaly entity.NewIPAnomaly
		var logTypes []string

		if err := rows.Scan(
			&anomaly.IP,
			&anomaly.FirstSeen,
			&anomaly.EventCount,
			&logTypes,
			&anomaly.Country,
		); err != nil {
			return nil, fmt.Errorf("scan new IP: %w", err)
		}

		anomaly.LogTypes = logTypes
		results = append(results, anomaly)
	}

	return results, nil
}

// GetHourlyEventCounts returns hourly event counts for baseline calculation
func (r *AnomaliesRepository) GetHourlyEventCounts(ctx context.Context, window time.Duration) ([]int64, error) {
	hours := int(window.Hours())

	query := `
		SELECT count() as cnt
		FROM events
		WHERE timestamp >= now() - INTERVAL ? HOUR
		GROUP BY toStartOfHour(timestamp)
		ORDER BY toStartOfHour(timestamp)
	`

	rows, err := r.conn.DB().Query(ctx, query, hours)
	if err != nil {
		return nil, fmt.Errorf("query hourly counts: %w", err)
	}
	defer rows.Close()

	var counts []int64
	for rows.Next() {
		var count int64
		if err := rows.Scan(&count); err != nil {
			return nil, fmt.Errorf("scan count: %w", err)
		}
		counts = append(counts, count)
	}

	return counts, nil
}

// GetRecentEventCounts returns event counts for recent hours
func (r *AnomaliesRepository) GetRecentEventCounts(ctx context.Context, window time.Duration) (map[time.Time]int64, error) {
	hours := int(window.Hours())
	if hours < 1 {
		hours = 1
	}

	query := `
		SELECT
			toStartOfHour(timestamp) as hour,
			count() as cnt
		FROM events
		WHERE timestamp >= now() - INTERVAL ? HOUR
		GROUP BY hour
		ORDER BY hour
	`

	rows, err := r.conn.DB().Query(ctx, query, hours)
	if err != nil {
		return nil, fmt.Errorf("query recent counts: %w", err)
	}
	defer rows.Close()

	counts := make(map[time.Time]int64)
	for rows.Next() {
		var hour time.Time
		var count int64
		if err := rows.Scan(&hour, &count); err != nil {
			return nil, fmt.Errorf("scan count: %w", err)
		}
		counts[hour] = count
	}

	return counts, nil
}

// RecordSpike saves a spike anomaly
func (r *AnomaliesRepository) RecordSpike(ctx context.Context, spike *entity.Spike) error {
	if spike.ID == uuid.Nil {
		spike.ID = uuid.New()
	}

	query := `
		INSERT INTO anomaly_spikes (
			id, timestamp, event_count, baseline, threshold,
			deviation, severity, log_type, detected_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	if err := r.conn.DB().Exec(ctx, query,
		spike.ID,
		spike.Timestamp,
		spike.EventCount,
		spike.Baseline,
		spike.Threshold,
		spike.Deviation,
		spike.Severity,
		spike.LogType,
		spike.DetectedAt,
	); err != nil {
		return fmt.Errorf("insert spike: %w", err)
	}

	return nil
}

// GetMultiVectorAttackers finds IPs using multiple attack vectors
func (r *AnomaliesRepository) GetMultiVectorAttackers(ctx context.Context, threshold int, window time.Duration) ([]entity.MultiVectorAttack, error) {
	hours := int(window.Hours())
	if hours < 1 {
		hours = 1
	}

	query := `
		SELECT
			src_ip,
			groupArray(DISTINCT log_type) as vectors,
			count() as event_count,
			min(timestamp) as first_seen,
			max(timestamp) as last_seen,
			any(geo_country) as country
		FROM events
		WHERE timestamp >= now() - INTERVAL ? HOUR
		  AND action = 'drop'
		GROUP BY src_ip
		HAVING length(vectors) >= ?
		ORDER BY event_count DESC
		LIMIT 50
	`

	rows, err := r.conn.DB().Query(ctx, query, hours, threshold)
	if err != nil {
		return nil, fmt.Errorf("query multi-vector: %w", err)
	}
	defer rows.Close()

	var results []entity.MultiVectorAttack
	for rows.Next() {
		var attack entity.MultiVectorAttack
		var vectors []string

		if err := rows.Scan(
			&attack.IP,
			&vectors,
			&attack.EventCount,
			&attack.FirstSeen,
			&attack.LastSeen,
			&attack.Country,
		); err != nil {
			return nil, fmt.Errorf("scan multi-vector: %w", err)
		}

		attack.Vectors = vectors
		results = append(results, attack)
	}

	return results, nil
}

// GetTargetedCampaigns finds multiple IPs targeting the same resource
func (r *AnomaliesRepository) GetTargetedCampaigns(ctx context.Context, threshold int, window time.Duration) ([]entity.TargetedCampaign, error) {
	hours := int(window.Hours())
	if hours < 1 {
		hours = 1
	}

	query := `
		SELECT
			coalesce(hostname, dst_ip) as target,
			groupArray(DISTINCT src_ip) as source_ips,
			count() as event_count,
			min(timestamp) as start_time,
			max(timestamp) as end_time
		FROM events
		WHERE timestamp >= now() - INTERVAL ? HOUR
		  AND action = 'drop'
		GROUP BY target
		HAVING length(source_ips) >= ?
		ORDER BY event_count DESC
		LIMIT 50
	`

	rows, err := r.conn.DB().Query(ctx, query, hours, threshold)
	if err != nil {
		return nil, fmt.Errorf("query campaigns: %w", err)
	}
	defer rows.Close()

	var results []entity.TargetedCampaign
	for rows.Next() {
		var campaign entity.TargetedCampaign
		var sourceIPs []string

		if err := rows.Scan(
			&campaign.Target,
			&sourceIPs,
			&campaign.EventCount,
			&campaign.StartTime,
			&campaign.EndTime,
		); err != nil {
			return nil, fmt.Errorf("scan campaign: %w", err)
		}

		campaign.SourceIPs = sourceIPs
		results = append(results, campaign)
	}

	return results, nil
}

// GetBruteForcePatterns detects brute force patterns
func (r *AnomaliesRepository) GetBruteForcePatterns(ctx context.Context, threshold int, window time.Duration) ([]entity.BruteForcePattern, error) {
	minutes := int(window.Minutes())
	if minutes < 1 {
		minutes = 5
	}

	query := `
		SELECT
			src_ip,
			coalesce(hostname, dst_ip) as target,
			count() as failed_attempts,
			min(timestamp) as first_attempt,
			max(timestamp) as last_attempt
		FROM events
		WHERE timestamp >= now() - INTERVAL ? MINUTE
		  AND action = 'drop'
		  AND (category = 'authentication' OR sub_category LIKE '%auth%' OR sub_category LIKE '%login%')
		GROUP BY src_ip, target
		HAVING failed_attempts >= ?
		ORDER BY failed_attempts DESC
		LIMIT 50
	`

	rows, err := r.conn.DB().Query(ctx, query, minutes, threshold)
	if err != nil {
		return nil, fmt.Errorf("query brute force: %w", err)
	}
	defer rows.Close()

	windowStr := fmt.Sprintf("%dm", minutes)
	var results []entity.BruteForcePattern
	for rows.Next() {
		var pattern entity.BruteForcePattern
		pattern.Window = windowStr

		if err := rows.Scan(
			&pattern.IP,
			&pattern.Target,
			&pattern.FailedAttempts,
			&pattern.FirstAttempt,
			&pattern.LastAttempt,
		); err != nil {
			return nil, fmt.Errorf("scan brute force: %w", err)
		}

		results = append(results, pattern)
	}

	return results, nil
}

// GetRecentAnomalies returns recently detected anomalies
func (r *AnomaliesRepository) GetRecentAnomalies(ctx context.Context, limit int) ([]entity.Anomaly, error) {
	query := `
		SELECT
			id,
			'spike' as type,
			severity,
			'' as ip,
			concat('Event spike: ', toString(event_count), ' events (', toString(round(deviation, 1)), 'σ)') as description,
			'' as details,
			detected_at,
			false as acknowledged
		FROM anomaly_spikes
		ORDER BY detected_at DESC
		LIMIT ?
	`

	rows, err := r.conn.DB().Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query recent anomalies: %w", err)
	}
	defer rows.Close()

	var results []entity.Anomaly
	for rows.Next() {
		var anomaly entity.Anomaly
		if err := rows.Scan(
			&anomaly.ID,
			&anomaly.Type,
			&anomaly.Severity,
			&anomaly.IP,
			&anomaly.Description,
			&anomaly.Details,
			&anomaly.DetectedAt,
			&anomaly.Acknowledged,
		); err != nil {
			return nil, fmt.Errorf("scan anomaly: %w", err)
		}
		results = append(results, anomaly)
	}

	return results, nil
}

// GetAnomalyStats returns anomaly statistics
func (r *AnomaliesRepository) GetAnomalyStats(ctx context.Context) (*anomalies.AnomalyStats, error) {
	stats := &anomalies.AnomalyStats{}

	// Total spikes
	query := `SELECT count() FROM anomaly_spikes`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.TotalDetected)

	// Spikes last 24h
	query = `SELECT count() FROM anomaly_spikes WHERE detected_at >= now() - INTERVAL 24 HOUR`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.SpikesLast24h)

	// New IPs last 24h (distinct source IPs first seen in last 24h)
	query = `
		SELECT count(DISTINCT src_ip)
		FROM events
		WHERE timestamp >= now() - INTERVAL 24 HOUR
		  AND src_ip NOT IN (
			SELECT DISTINCT src_ip
			FROM events
			WHERE timestamp < now() - INTERVAL 24 HOUR
		  )
	`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.NewIPsLast24h)

	// Critical spikes
	query = `SELECT count() FROM anomaly_spikes WHERE severity = 'critical'`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.CriticalCount)

	// High severity spikes
	query = `SELECT count() FROM anomaly_spikes WHERE severity = 'high'`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.HighCount)

	return stats, nil
}
