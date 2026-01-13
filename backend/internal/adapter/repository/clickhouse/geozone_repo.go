package clickhouse

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// GeoZoneRepository handles GeoZone config persistence in ClickHouse
type GeoZoneRepository struct {
	conn *Connection
}

// NewGeoZoneRepository creates a new GeoZone repository
func NewGeoZoneRepository(conn *Connection) *GeoZoneRepository {
	return &GeoZoneRepository{conn: conn}
}

// GetGeoZoneConfig retrieves the current GeoZone configuration
func (r *GeoZoneRepository) GetGeoZoneConfig() (*entity.GeoZoneConfig, error) {
	ctx := context.Background()

	query := `
		SELECT
			enabled,
			authorized_countries,
			hostile_countries,
			default_policy,
			waf_threshold_hzone,
			waf_threshold_zone,
			threat_score_threshold
		FROM vigilance_x.geozone_config
		WHERE id = 1
		ORDER BY version DESC
		LIMIT 1
	`

	var config entity.GeoZoneConfig
	var enabled uint8
	var wafThresholdHzone, wafThresholdZone, threatScoreThreshold uint8
	var authorizedCountries, hostileCountries []string

	row := r.conn.QueryRow(ctx, query)
	err := row.Scan(
		&enabled,
		&authorizedCountries,
		&hostileCountries,
		&config.DefaultPolicy,
		&wafThresholdHzone,
		&wafThresholdZone,
		&threatScoreThreshold,
	)

	if err != nil {
		// Log the error and return default config
		slog.Warn("[GEOZONE_REPO] GetGeoZoneConfig query failed, returning default", "error", err)
		return entity.DefaultGeoZoneConfig(), nil
	}

	config.Enabled = enabled == 1
	config.AuthorizedCountries = authorizedCountries
	config.HostileCountries = hostileCountries
	config.WAFThresholdHzone = int(wafThresholdHzone)
	config.WAFThresholdZone = int(wafThresholdZone)
	config.ThreatScoreThreshold = int(threatScoreThreshold)

	slog.Info("[GEOZONE_REPO] GetGeoZoneConfig returned",
		"enabled", config.Enabled,
		"auth_countries", len(config.AuthorizedCountries),
		"hostile_countries", len(config.HostileCountries),
		"default_policy", config.DefaultPolicy)

	return &config, nil
}

// SaveGeoZoneConfig saves the GeoZone configuration
func (r *GeoZoneRepository) SaveGeoZoneConfig(config *entity.GeoZoneConfig) error {
	ctx := context.Background()

	// Get current version
	var currentVersion uint64
	row := r.conn.QueryRow(ctx, "SELECT max(version) FROM vigilance_x.geozone_config WHERE id = 1")
	if err := row.Scan(&currentVersion); err != nil {
		// If no rows, start at version 0
		currentVersion = 0
	}

	enabled := uint8(0)
	if config.Enabled {
		enabled = 1
	}

	// Ensure slices are not nil (ClickHouse requires non-nil arrays)
	authorizedCountries := config.AuthorizedCountries
	if authorizedCountries == nil {
		authorizedCountries = []string{}
	}
	hostileCountries := config.HostileCountries
	if hostileCountries == nil {
		hostileCountries = []string{}
	}

	query := `
		INSERT INTO vigilance_x.geozone_config (
			id,
			enabled,
			authorized_countries,
			hostile_countries,
			default_policy,
			waf_threshold_hzone,
			waf_threshold_zone,
			threat_score_threshold,
			updated_at,
			version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, now(), ?)
	`

	slog.Info("[GEOZONE_REPO] Executing INSERT",
		"version", currentVersion+1,
		"enabled", enabled,
		"auth_countries", authorizedCountries,
		"hostile_countries", hostileCountries,
		"default_policy", config.DefaultPolicy)

	err := r.conn.Exec(ctx, query,
		1,
		enabled,
		authorizedCountries,
		hostileCountries,
		config.DefaultPolicy,
		config.WAFThresholdHzone,
		config.WAFThresholdZone,
		config.ThreatScoreThreshold,
		currentVersion+1,
	)

	if err != nil {
		slog.Error("[GEOZONE_REPO] INSERT failed", "error", err)
		return fmt.Errorf("save geozone config: %w", err)
	}

	slog.Info("[GEOZONE_REPO] INSERT succeeded", "version", currentVersion+1)
	return nil
}

// PendingBansRepository handles pending bans persistence
type PendingBansRepository struct {
	conn *Connection
}

// NewPendingBansRepository creates a new pending bans repository
func NewPendingBansRepository(conn *Connection) *PendingBansRepository {
	return &PendingBansRepository{conn: conn}
}

// CreatePendingBan creates a new pending ban
func (r *PendingBansRepository) CreatePendingBan(ctx context.Context, ban *entity.PendingBan) error {
	query := `
		INSERT INTO vigilance_x.pending_bans (
			id, ip, country, geo_zone, threat_score, threat_sources,
			event_count, first_event, last_event, trigger_rule, reason,
			status, created_at
		) VALUES (
			generateUUIDv4(), ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?,
			'pending', now()
		)
	`

	return r.conn.Exec(ctx, query,
		ban.IP,
		ban.Country,
		ban.GeoZone,
		ban.ThreatScore,
		ban.ThreatSources,
		ban.EventCount,
		ban.FirstEvent,
		ban.LastEvent,
		ban.TriggerRule,
		ban.Reason,
	)
}

// GetPendingBans retrieves all pending bans
func (r *PendingBansRepository) GetPendingBans(ctx context.Context) ([]entity.PendingBan, error) {
	query := `
		SELECT
			id, ip, country, geo_zone, threat_score, threat_sources,
			event_count, first_event, last_event, trigger_rule, reason,
			status, created_at, reviewed_at, reviewed_by, review_note
		FROM vigilance_x.pending_bans
		WHERE status = 'pending'
		ORDER BY created_at DESC
		LIMIT 100
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bans []entity.PendingBan
	for rows.Next() {
		var ban entity.PendingBan
		err := rows.Scan(
			&ban.ID,
			&ban.IP,
			&ban.Country,
			&ban.GeoZone,
			&ban.ThreatScore,
			&ban.ThreatSources,
			&ban.EventCount,
			&ban.FirstEvent,
			&ban.LastEvent,
			&ban.TriggerRule,
			&ban.Reason,
			&ban.Status,
			&ban.CreatedAt,
			&ban.ReviewedAt,
			&ban.ReviewedBy,
			&ban.ReviewNote,
		)
		if err != nil {
			continue
		}
		bans = append(bans, ban)
	}

	return bans, nil
}

// GetPendingBanByIP retrieves a pending ban by IP
func (r *PendingBansRepository) GetPendingBanByIP(ctx context.Context, ip string) (*entity.PendingBan, error) {
	query := `
		SELECT
			id, ip, country, geo_zone, threat_score, threat_sources,
			event_count, first_event, last_event, trigger_rule, reason,
			status, created_at, reviewed_at, reviewed_by, review_note
		FROM vigilance_x.pending_bans
		WHERE ip = ? AND status = 'pending'
		ORDER BY created_at DESC
		LIMIT 1
	`

	var ban entity.PendingBan
	row := r.conn.QueryRow(ctx, query, ip)
	err := row.Scan(
		&ban.ID,
		&ban.IP,
		&ban.Country,
		&ban.GeoZone,
		&ban.ThreatScore,
		&ban.ThreatSources,
		&ban.EventCount,
		&ban.FirstEvent,
		&ban.LastEvent,
		&ban.TriggerRule,
		&ban.Reason,
		&ban.Status,
		&ban.CreatedAt,
		&ban.ReviewedAt,
		&ban.ReviewedBy,
		&ban.ReviewNote,
	)

	if err != nil {
		return nil, nil // Not found
	}

	return &ban, nil
}

// ApprovePendingBan approves a pending ban
func (r *PendingBansRepository) ApprovePendingBan(ctx context.Context, id string, reviewedBy string, note string) error {
	query := `
		ALTER TABLE vigilance_x.pending_bans
		UPDATE
			status = 'approved',
			reviewed_at = now(),
			reviewed_by = ?,
			review_note = ?
		WHERE id = ?
	`

	return r.conn.Exec(ctx, query, reviewedBy, note, id)
}

// RejectPendingBan rejects a pending ban
func (r *PendingBansRepository) RejectPendingBan(ctx context.Context, id string, reviewedBy string, note string) error {
	query := `
		ALTER TABLE vigilance_x.pending_bans
		UPDATE
			status = 'rejected',
			reviewed_at = now(),
			reviewed_by = ?,
			review_note = ?
		WHERE id = ?
	`

	return r.conn.Exec(ctx, query, reviewedBy, note, id)
}

// GetPendingBanStats retrieves pending ban statistics
func (r *PendingBansRepository) GetPendingBanStats(ctx context.Context) (*entity.PendingBanStats, error) {
	query := `
		SELECT
			count() as total,
			countIf(threat_score >= 70) as high,
			countIf(threat_score >= 30 AND threat_score < 70) as medium,
			countIf(threat_score < 30) as low,
			min(created_at) as oldest
		FROM vigilance_x.pending_bans
		WHERE status = 'pending'
	`

	var stats entity.PendingBanStats
	row := r.conn.QueryRow(ctx, query)
	err := row.Scan(
		&stats.TotalPending,
		&stats.HighThreat,
		&stats.MediumThreat,
		&stats.LowThreat,
		&stats.OldestPending,
	)

	if err != nil {
		return nil, err
	}

	return &stats, nil
}
