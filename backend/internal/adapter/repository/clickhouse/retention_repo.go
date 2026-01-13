package clickhouse

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// RetentionRepository handles retention settings persistence in ClickHouse
type RetentionRepository struct {
	conn *Connection
}

// NewRetentionRepository creates a new retention repository
func NewRetentionRepository(conn *Connection) *RetentionRepository {
	return &RetentionRepository{conn: conn}
}

// GetRetentionSettings retrieves the current retention configuration
func (r *RetentionRepository) GetRetentionSettings(ctx context.Context) (*entity.RetentionSettings, error) {
	query := `
		SELECT
			events_retention_days,
			modsec_logs_retention_days,
			firewall_events_retention_days,
			vpn_events_retention_days,
			heartbeat_events_retention_days,
			atp_events_retention_days,
			antivirus_events_retention_days,
			ban_history_retention_days,
			audit_log_retention_days,
			retention_enabled,
			last_cleanup,
			cleanup_interval_hours,
			updated_at,
			updated_by
		FROM vigilance_x.retention_settings
		WHERE id = 1
		ORDER BY version DESC
		LIMIT 1
	`

	var settings entity.RetentionSettings
	var retentionEnabled uint8
	var eventsRetention, modsecRetention, firewallRetention, vpnRetention, heartbeatRetention uint16
	var atpRetention, antivirusRetention, banHistoryRetention, auditLogRetention uint16
	var cleanupIntervalHours uint8

	row := r.conn.QueryRow(ctx, query)
	err := row.Scan(
		&eventsRetention,
		&modsecRetention,
		&firewallRetention,
		&vpnRetention,
		&heartbeatRetention,
		&atpRetention,
		&antivirusRetention,
		&banHistoryRetention,
		&auditLogRetention,
		&retentionEnabled,
		&settings.LastCleanup,
		&cleanupIntervalHours,
		&settings.UpdatedAt,
		&settings.UpdatedBy,
	)

	if err != nil {
		slog.Warn("[RETENTION_REPO] GetRetentionSettings query failed, returning default", "error", err)
		return entity.DefaultRetentionSettings(), nil
	}

	settings.EventsRetentionDays = int(eventsRetention)
	settings.ModsecLogsRetentionDays = int(modsecRetention)
	settings.FirewallEventsRetentionDays = int(firewallRetention)
	settings.VpnEventsRetentionDays = int(vpnRetention)
	settings.HeartbeatEventsRetentionDays = int(heartbeatRetention)
	settings.AtpEventsRetentionDays = int(atpRetention)
	settings.AntivirusEventsRetentionDays = int(antivirusRetention)
	settings.BanHistoryRetentionDays = int(banHistoryRetention)
	settings.AuditLogRetentionDays = int(auditLogRetention)
	settings.RetentionEnabled = retentionEnabled == 1
	settings.CleanupIntervalHours = int(cleanupIntervalHours)

	slog.Info("[RETENTION_REPO] GetRetentionSettings returned",
		"enabled", settings.RetentionEnabled,
		"events_days", settings.EventsRetentionDays,
		"last_cleanup", settings.LastCleanup)

	return &settings, nil
}

// SaveRetentionSettings saves the retention configuration
func (r *RetentionRepository) SaveRetentionSettings(ctx context.Context, settings *entity.RetentionSettings, updatedBy string) error {
	// Get current version
	var currentVersion uint64
	row := r.conn.QueryRow(ctx, "SELECT max(version) FROM vigilance_x.retention_settings WHERE id = 1")
	if err := row.Scan(&currentVersion); err != nil {
		currentVersion = 0
	}

	enabled := uint8(0)
	if settings.RetentionEnabled {
		enabled = 1
	}

	query := `
		INSERT INTO vigilance_x.retention_settings (
			id,
			events_retention_days,
			modsec_logs_retention_days,
			firewall_events_retention_days,
			vpn_events_retention_days,
			heartbeat_events_retention_days,
			atp_events_retention_days,
			antivirus_events_retention_days,
			ban_history_retention_days,
			audit_log_retention_days,
			retention_enabled,
			cleanup_interval_hours,
			updated_at,
			updated_by,
			version
		) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now(), ?, ?)
	`

	slog.Info("[RETENTION_REPO] Saving retention settings",
		"version", currentVersion+1,
		"enabled", enabled,
		"events_days", settings.EventsRetentionDays,
		"updated_by", updatedBy)

	err := r.conn.Exec(ctx, query,
		settings.EventsRetentionDays,
		settings.ModsecLogsRetentionDays,
		settings.FirewallEventsRetentionDays,
		settings.VpnEventsRetentionDays,
		settings.HeartbeatEventsRetentionDays,
		settings.AtpEventsRetentionDays,
		settings.AntivirusEventsRetentionDays,
		settings.BanHistoryRetentionDays,
		settings.AuditLogRetentionDays,
		enabled,
		settings.CleanupIntervalHours,
		updatedBy,
		currentVersion+1,
	)

	if err != nil {
		slog.Error("[RETENTION_REPO] Save failed", "error", err)
		return fmt.Errorf("save retention settings: %w", err)
	}

	slog.Info("[RETENTION_REPO] Save succeeded", "version", currentVersion+1)
	return nil
}

// UpdateLastCleanup updates the last cleanup timestamp
func (r *RetentionRepository) UpdateLastCleanup(ctx context.Context) error {
	// Get current version
	var currentVersion uint64
	row := r.conn.QueryRow(ctx, "SELECT max(version) FROM vigilance_x.retention_settings WHERE id = 1")
	if err := row.Scan(&currentVersion); err != nil {
		return fmt.Errorf("get version: %w", err)
	}

	// Get current settings first
	settings, err := r.GetRetentionSettings(ctx)
	if err != nil {
		return fmt.Errorf("get settings: %w", err)
	}

	enabled := uint8(0)
	if settings.RetentionEnabled {
		enabled = 1
	}

	query := `
		INSERT INTO vigilance_x.retention_settings (
			id,
			events_retention_days,
			modsec_logs_retention_days,
			firewall_events_retention_days,
			vpn_events_retention_days,
			heartbeat_events_retention_days,
			atp_events_retention_days,
			antivirus_events_retention_days,
			ban_history_retention_days,
			audit_log_retention_days,
			retention_enabled,
			last_cleanup,
			cleanup_interval_hours,
			updated_at,
			updated_by,
			version
		) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now(), ?, now(), 'cleanup_worker', ?)
	`

	return r.conn.Exec(ctx, query,
		settings.EventsRetentionDays,
		settings.ModsecLogsRetentionDays,
		settings.FirewallEventsRetentionDays,
		settings.VpnEventsRetentionDays,
		settings.HeartbeatEventsRetentionDays,
		settings.AtpEventsRetentionDays,
		settings.AntivirusEventsRetentionDays,
		settings.BanHistoryRetentionDays,
		settings.AuditLogRetentionDays,
		enabled,
		settings.CleanupIntervalHours,
		currentVersion+1,
	)
}

// GetTableRowCount returns the number of rows in a table
func (r *RetentionRepository) GetTableRowCount(ctx context.Context, tableName string) (int64, error) {
	query := fmt.Sprintf("SELECT count() FROM vigilance_x.%s", tableName)
	var count uint64
	row := r.conn.QueryRow(ctx, query)
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return int64(count), nil
}

// DeleteOldRecords deletes records older than retention days for a specific table
func (r *RetentionRepository) DeleteOldRecords(ctx context.Context, tableName string, timestampColumn string, retentionDays int) (int64, error) {
	// Get count before
	countBefore, err := r.GetTableRowCount(ctx, tableName)
	if err != nil {
		slog.Warn("[RETENTION_REPO] Failed to get count before cleanup", "table", tableName, "error", err)
		countBefore = 0
	}

	// For MergeTree tables, we use ALTER TABLE DELETE
	query := fmt.Sprintf(
		"ALTER TABLE vigilance_x.%s DELETE WHERE %s < now() - INTERVAL %d DAY",
		tableName, timestampColumn, retentionDays,
	)

	slog.Info("[RETENTION_REPO] Executing cleanup",
		"table", tableName,
		"column", timestampColumn,
		"retention_days", retentionDays,
		"rows_before", countBefore)

	if err := r.conn.Exec(ctx, query); err != nil {
		return 0, fmt.Errorf("delete old records from %s: %w", tableName, err)
	}

	// Note: The actual deletion happens asynchronously in ClickHouse
	// We return the count before as an estimate
	return countBefore, nil
}

// GetStorageStats returns disk usage statistics
func (r *RetentionRepository) GetStorageStats(ctx context.Context) (*entity.StorageStats, error) {
	// Get table sizes
	query := `
		SELECT
			table,
			sum(bytes_on_disk) as size_bytes
		FROM system.parts
		WHERE database = 'vigilance_x' AND active
		GROUP BY table
		ORDER BY size_bytes DESC
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query table sizes: %w", err)
	}
	defer rows.Close()

	stats := &entity.StorageStats{
		TablesSize: make(map[string]int64),
	}

	var totalSize int64
	for rows.Next() {
		var tableName string
		var sizeBytes int64
		if err := rows.Scan(&tableName, &sizeBytes); err != nil {
			continue
		}
		stats.TablesSize[tableName] = sizeBytes
		totalSize += sizeBytes
	}

	stats.UsedBytes = totalSize

	// Get disk info (if available)
	diskQuery := `
		SELECT
			total_space,
			free_space
		FROM system.disks
		WHERE name = 'default'
		LIMIT 1
	`

	row := r.conn.QueryRow(ctx, diskQuery)
	var totalSpace, freeSpace uint64
	if err := row.Scan(&totalSpace, &freeSpace); err == nil {
		stats.TotalBytes = int64(totalSpace)
		stats.AvailableBytes = int64(freeSpace)
		if totalSpace > 0 {
			stats.UsedPercent = float64(totalSpace-freeSpace) / float64(totalSpace) * 100
		}
	}

	return stats, nil
}

// TableCleanupConfig maps table names to their timestamp columns
var TableCleanupConfig = map[string]string{
	"events":           "timestamp",
	"modsec_logs":      "timestamp",
	"firewall_events":  "timestamp",
	"vpn_events":       "timestamp",
	"heartbeat_events": "timestamp",
	"atp_events":       "timestamp",
	"antivirus_events": "timestamp",
	"ban_history":      "timestamp",
	"audit_log":        "timestamp",
}
