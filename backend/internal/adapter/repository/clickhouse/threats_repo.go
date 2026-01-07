package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// ThreatsRepository handles threat data persistence in ClickHouse
type ThreatsRepository struct {
	conn *Connection
}

// NewThreatsRepository creates a new threats repository
func NewThreatsRepository(conn *Connection) *ThreatsRepository {
	return &ThreatsRepository{conn: conn}
}

// GetThreatScore retrieves the threat score for an IP
func (r *ThreatsRepository) GetThreatScore(ctx context.Context, ip string) (*entity.ThreatScore, error) {
	query := `
		SELECT
			ip,
			aggregated_score,
			threat_level,
			confidence,
			country,
			asn,
			isp,
			is_tor,
			abuseipdb_score,
			virustotal_score,
			otx_score,
			tags,
			malware_families,
			adversaries,
			last_checked
		FROM ip_threat_scores FINAL
		WHERE ip = ?
		LIMIT 1
	`

	row := r.conn.DB().QueryRow(ctx, query, ip)

	var score entity.ThreatScore
	var tags, malwareFamilies, adversaries []string

	if err := row.Scan(
		&score.IP,
		&score.AggregatedScore,
		&score.ThreatLevel,
		&score.Confidence,
		&score.Country,
		&score.ASN,
		&score.ISP,
		&score.IsTor,
		&score.AbuseIPDBScore,
		&score.VirusTotalScore,
		&score.OTXScore,
		&tags,
		&malwareFamilies,
		&adversaries,
		&score.LastChecked,
	); err != nil {
		return nil, fmt.Errorf("scan threat score: %w", err)
	}

	score.Tags = tags
	score.MalwareFamilies = malwareFamilies
	score.Adversaries = adversaries

	return &score, nil
}

// UpsertThreatScore creates or updates a threat score
// v1.6: Added support for 7 threat intel providers
func (r *ThreatsRepository) UpsertThreatScore(ctx context.Context, score *entity.ThreatScore) error {
	query := `
		INSERT INTO ip_threat_scores (
			ip, aggregated_score, threat_level, confidence,
			country, asn, isp, is_tor,
			abuseipdb_score, virustotal_score, otx_score,
			greynoise_score, ipsum_score, criminalip_score, pulsedive_score,
			is_benign, is_vpn, is_proxy, in_blocklists,
			tags, malware_families, adversaries,
			last_checked, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	tags := score.Tags
	if tags == nil {
		tags = []string{}
	}
	malwareFamilies := score.MalwareFamilies
	if malwareFamilies == nil {
		malwareFamilies = []string{}
	}
	adversaries := score.Adversaries
	if adversaries == nil {
		adversaries = []string{}
	}

	if err := r.conn.DB().Exec(ctx, query,
		score.IP,
		score.AggregatedScore,
		score.ThreatLevel,
		score.Confidence,
		score.Country,
		score.ASN,
		score.ISP,
		score.IsTor,
		// Core providers
		score.AbuseIPDBScore,
		score.VirusTotalScore,
		score.OTXScore,
		// v1.6 providers
		score.GreyNoiseScore,
		score.IPSumScore,
		score.CriminalIPScore,
		score.PulsediveScore,
		// v1.6 flags
		score.IsBenign,
		score.IsVPN,
		score.IsProxy,
		score.InBlocklists,
		tags,
		malwareFamilies,
		adversaries,
		score.LastChecked,
		time.Now(),
	); err != nil {
		return fmt.Errorf("upsert threat score: %w", err)
	}

	return nil
}

// GetTopThreats returns IPs with highest threat scores
func (r *ThreatsRepository) GetTopThreats(ctx context.Context, limit int) ([]entity.ThreatScore, error) {
	query := `
		SELECT
			ip,
			aggregated_score,
			threat_level,
			confidence,
			country,
			asn,
			isp,
			is_tor,
			abuseipdb_score,
			virustotal_score,
			otx_score,
			tags,
			malware_families,
			adversaries,
			last_checked
		FROM ip_threat_scores FINAL
		WHERE aggregated_score > 0
		ORDER BY aggregated_score DESC
		LIMIT ?
	`

	rows, err := r.conn.DB().Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query top threats: %w", err)
	}
	defer rows.Close()

	var scores []entity.ThreatScore
	for rows.Next() {
		var score entity.ThreatScore
		var tags, malwareFamilies, adversaries []string

		if err := rows.Scan(
			&score.IP,
			&score.AggregatedScore,
			&score.ThreatLevel,
			&score.Confidence,
			&score.Country,
			&score.ASN,
			&score.ISP,
			&score.IsTor,
			&score.AbuseIPDBScore,
			&score.VirusTotalScore,
			&score.OTXScore,
			&tags,
			&malwareFamilies,
			&adversaries,
			&score.LastChecked,
		); err != nil {
			return nil, fmt.Errorf("scan threat: %w", err)
		}

		score.Tags = tags
		score.MalwareFamilies = malwareFamilies
		score.Adversaries = adversaries

		scores = append(scores, score)
	}

	return scores, nil
}

// GetThreatsByLevel returns threats filtered by level
func (r *ThreatsRepository) GetThreatsByLevel(ctx context.Context, level string, limit int) ([]entity.ThreatScore, error) {
	query := `
		SELECT
			ip,
			aggregated_score,
			threat_level,
			confidence,
			country,
			asn,
			isp,
			is_tor,
			abuseipdb_score,
			virustotal_score,
			otx_score,
			tags,
			malware_families,
			adversaries,
			last_checked
		FROM ip_threat_scores FINAL
		WHERE threat_level = ?
		ORDER BY aggregated_score DESC
		LIMIT ?
	`

	rows, err := r.conn.DB().Query(ctx, query, level, limit)
	if err != nil {
		return nil, fmt.Errorf("query threats by level: %w", err)
	}
	defer rows.Close()

	var scores []entity.ThreatScore
	for rows.Next() {
		var score entity.ThreatScore
		var tags, malwareFamilies, adversaries []string

		if err := rows.Scan(
			&score.IP,
			&score.AggregatedScore,
			&score.ThreatLevel,
			&score.Confidence,
			&score.Country,
			&score.ASN,
			&score.ISP,
			&score.IsTor,
			&score.AbuseIPDBScore,
			&score.VirusTotalScore,
			&score.OTXScore,
			&tags,
			&malwareFamilies,
			&adversaries,
			&score.LastChecked,
		); err != nil {
			return nil, fmt.Errorf("scan threat: %w", err)
		}

		score.Tags = tags
		score.MalwareFamilies = malwareFamilies
		score.Adversaries = adversaries

		scores = append(scores, score)
	}

	return scores, nil
}

// GetThreatStats returns aggregated threat statistics
func (r *ThreatsRepository) GetThreatStats(ctx context.Context) (*entity.ThreatStats, error) {
	stats := &entity.ThreatStats{}

	// Total tracked IPs
	query := `SELECT count() FROM ip_threat_scores FINAL`
	if err := r.conn.DB().QueryRow(ctx, query).Scan(&stats.TotalTracked); err != nil {
		return nil, fmt.Errorf("count total: %w", err)
	}

	// Count by threat level
	query = `SELECT count() FROM ip_threat_scores FINAL WHERE threat_level = 'critical'`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.CriticalCount)

	query = `SELECT count() FROM ip_threat_scores FINAL WHERE threat_level = 'high'`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.HighCount)

	query = `SELECT count() FROM ip_threat_scores FINAL WHERE threat_level = 'medium'`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.MediumCount)

	query = `SELECT count() FROM ip_threat_scores FINAL WHERE threat_level = 'low'`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.LowCount)

	// Tor exit nodes
	query = `SELECT count() FROM ip_threat_scores FINAL WHERE is_tor = 1`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.TorExitNodes)

	// Checks in last 24h
	query = `SELECT count() FROM ip_threat_scores FINAL WHERE last_checked >= now() - INTERVAL 24 HOUR`
	r.conn.DB().QueryRow(ctx, query).Scan(&stats.ChecksLast24h)

	return stats, nil
}

// GetTorExitNodes returns IPs identified as Tor exit nodes
func (r *ThreatsRepository) GetTorExitNodes(ctx context.Context, limit int) ([]entity.ThreatScore, error) {
	query := `
		SELECT
			ip,
			aggregated_score,
			threat_level,
			country,
			last_checked
		FROM ip_threat_scores FINAL
		WHERE is_tor = 1
		ORDER BY aggregated_score DESC
		LIMIT ?
	`

	rows, err := r.conn.DB().Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query tor nodes: %w", err)
	}
	defer rows.Close()

	var scores []entity.ThreatScore
	for rows.Next() {
		var score entity.ThreatScore
		score.IsTor = true

		if err := rows.Scan(
			&score.IP,
			&score.AggregatedScore,
			&score.ThreatLevel,
			&score.Country,
			&score.LastChecked,
		); err != nil {
			return nil, fmt.Errorf("scan tor node: %w", err)
		}

		scores = append(scores, score)
	}

	return scores, nil
}

// GetIPsWithMalware returns IPs associated with malware families
func (r *ThreatsRepository) GetIPsWithMalware(ctx context.Context, limit int) ([]entity.ThreatScore, error) {
	query := `
		SELECT
			ip,
			aggregated_score,
			threat_level,
			malware_families,
			adversaries,
			last_checked
		FROM ip_threat_scores FINAL
		WHERE length(malware_families) > 0
		ORDER BY aggregated_score DESC
		LIMIT ?
	`

	rows, err := r.conn.DB().Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query malware IPs: %w", err)
	}
	defer rows.Close()

	var scores []entity.ThreatScore
	for rows.Next() {
		var score entity.ThreatScore
		var malwareFamilies, adversaries []string

		if err := rows.Scan(
			&score.IP,
			&score.AggregatedScore,
			&score.ThreatLevel,
			&malwareFamilies,
			&adversaries,
			&score.LastChecked,
		); err != nil {
			return nil, fmt.Errorf("scan malware IP: %w", err)
		}

		score.MalwareFamilies = malwareFamilies
		score.Adversaries = adversaries

		scores = append(scores, score)
	}

	return scores, nil
}

// DeleteOldScores removes scores older than specified duration
func (r *ThreatsRepository) DeleteOldScores(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)

	query := `
		ALTER TABLE ip_threat_scores DELETE
		WHERE last_checked < ?
	`

	if err := r.conn.DB().Exec(ctx, query, cutoff); err != nil {
		return 0, fmt.Errorf("delete old scores: %w", err)
	}

	// Note: ClickHouse DELETE is async, can't get exact count
	return 0, nil
}
