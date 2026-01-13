package clickhouse

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	crowdsec "github.com/kr1s57/vigilancex/internal/usecase/crowdsec"
)

// CrowdSecBlocklistRepository handles CrowdSec blocklist persistence in ClickHouse
type CrowdSecBlocklistRepository struct {
	conn *Connection
}

// NewCrowdSecBlocklistRepository creates a new repository
func NewCrowdSecBlocklistRepository(conn *Connection) *CrowdSecBlocklistRepository {
	return &CrowdSecBlocklistRepository{conn: conn}
}

// GetConfig retrieves the current CrowdSec blocklist configuration
func (r *CrowdSecBlocklistRepository) GetConfig(ctx context.Context) (*crowdsec.BlocklistConfig, error) {
	query := `
		SELECT
			api_key,
			enabled,
			sync_interval_hours,
			xgs_group_name,
			enabled_lists,
			last_sync,
			total_ips
		FROM vigilance_x.crowdsec_blocklist_config
		WHERE id = 1
		ORDER BY version DESC
		LIMIT 1
	`

	var apiKey, xgsGroupName string
	var enabled, syncInterval uint8
	var enabledLists []string
	var lastSync time.Time
	var totalIPs uint32

	row := r.conn.QueryRow(ctx, query)
	err := row.Scan(
		&apiKey,
		&enabled,
		&syncInterval,
		&xgsGroupName,
		&enabledLists,
		&lastSync,
		&totalIPs,
	)

	if err != nil {
		slog.Warn("[CROWDSEC_REPO] GetConfig query failed, returning default", "error", err)
		return &crowdsec.BlocklistConfig{
			Enabled:           false,
			SyncIntervalHours: 6,
			XGSGroupName:      "grp_VGX-CrowdSec",
			EnabledLists:      []string{},
		}, nil
	}

	config := &crowdsec.BlocklistConfig{
		APIKey:            apiKey,
		Enabled:           enabled == 1,
		SyncIntervalHours: int(syncInterval),
		XGSGroupName:      xgsGroupName,
		EnabledLists:      enabledLists,
		LastSync:          lastSync,
		TotalIPs:          int(totalIPs),
	}

	slog.Debug("[CROWDSEC_REPO] GetConfig returned",
		"enabled", config.Enabled,
		"enabled_lists", len(config.EnabledLists),
		"last_sync", config.LastSync)

	return config, nil
}

// SaveConfig saves the CrowdSec blocklist configuration
func (r *CrowdSecBlocklistRepository) SaveConfig(ctx context.Context, config *crowdsec.BlocklistConfig) error {
	// Get current version
	var currentVersion uint64
	row := r.conn.QueryRow(ctx, "SELECT max(version) FROM vigilance_x.crowdsec_blocklist_config WHERE id = 1")
	if err := row.Scan(&currentVersion); err != nil {
		currentVersion = 0
	}

	enabled := uint8(0)
	if config.Enabled {
		enabled = 1
	}

	// Handle nil slice
	enabledLists := config.EnabledLists
	if enabledLists == nil {
		enabledLists = []string{}
	}

	query := `
		INSERT INTO vigilance_x.crowdsec_blocklist_config (
			id,
			api_key,
			enabled,
			sync_interval_hours,
			xgs_group_name,
			enabled_lists,
			last_sync,
			total_ips,
			updated_at,
			updated_by,
			version
		) VALUES (1, ?, ?, ?, ?, ?, ?, ?, now(), 'api', ?)
	`

	slog.Info("[CROWDSEC_REPO] Saving config",
		"version", currentVersion+1,
		"enabled", enabled,
		"enabled_lists", len(enabledLists))

	err := r.conn.Exec(ctx, query,
		config.APIKey,
		enabled,
		config.SyncIntervalHours,
		config.XGSGroupName,
		enabledLists,
		config.LastSync,
		config.TotalIPs,
		currentVersion+1,
	)

	if err != nil {
		slog.Error("[CROWDSEC_REPO] SaveConfig failed", "error", err)
		return fmt.Errorf("save crowdsec config: %w", err)
	}

	slog.Info("[CROWDSEC_REPO] SaveConfig succeeded", "version", currentVersion+1)
	return nil
}

// GetSyncedIPs returns all currently synced IPs
func (r *CrowdSecBlocklistRepository) GetSyncedIPs(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT ip
		FROM vigilance_x.crowdsec_synced_ips
		FINAL
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query synced ips: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// SaveSyncedIPs saves the synced IPs for a blocklist
func (r *CrowdSecBlocklistRepository) SaveSyncedIPs(ctx context.Context, ips []string, blocklistID string) error {
	if len(ips) == 0 {
		return nil
	}

	// Get current version for this blocklist
	var currentVersion uint64
	row := r.conn.QueryRow(ctx,
		"SELECT max(version) FROM vigilance_x.crowdsec_synced_ips WHERE blocklist_id = ?",
		blocklistID)
	if err := row.Scan(&currentVersion); err != nil {
		currentVersion = 0
	}
	newVersion := currentVersion + 1

	// Delete old IPs for this blocklist first (using version)
	// In ReplacingMergeTree, we insert with higher version

	// Batch insert new IPs
	batch, err := r.conn.PrepareBatch(ctx, `
		INSERT INTO vigilance_x.crowdsec_synced_ips (ip, blocklist_id, blocklist_name, synced_at, version)
	`)
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}

	now := time.Now()
	for _, ip := range ips {
		if err := batch.Append(ip, blocklistID, blocklistID, now, newVersion); err != nil {
			slog.Warn("[CROWDSEC_REPO] Failed to append IP to batch", "ip", ip, "error", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("send batch: %w", err)
	}

	slog.Info("[CROWDSEC_REPO] Saved synced IPs",
		"blocklist_id", blocklistID,
		"count", len(ips),
		"version", newVersion)

	return nil
}

// GetSyncHistory returns recent sync history
func (r *CrowdSecBlocklistRepository) GetSyncHistory(ctx context.Context, limit int) ([]crowdsec.SyncHistoryEntry, error) {
	query := `
		SELECT
			id,
			timestamp,
			blocklist_id,
			blocklist_name,
			ips_downloaded,
			ips_added,
			ips_removed,
			duration_ms,
			success,
			error
		FROM vigilance_x.crowdsec_sync_history
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := r.conn.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query sync history: %w", err)
	}
	defer rows.Close()

	var history []crowdsec.SyncHistoryEntry
	for rows.Next() {
		var entry crowdsec.SyncHistoryEntry
		var id uuid.UUID
		var ipsDownloaded, ipsAdded, ipsRemoved, durationMs uint32
		var success uint8
		var errStr string

		err := rows.Scan(
			&id,
			&entry.Timestamp,
			&entry.BlocklistID,
			&entry.BlocklistName,
			&ipsDownloaded,
			&ipsAdded,
			&ipsRemoved,
			&durationMs,
			&success,
			&errStr,
		)
		if err != nil {
			slog.Warn("[CROWDSEC_REPO] Failed to scan history row", "error", err)
			continue
		}

		entry.ID = id.String()
		entry.IPsDownloaded = int(ipsDownloaded)
		entry.IPsAdded = int(ipsAdded)
		entry.IPsRemoved = int(ipsRemoved)
		entry.DurationMs = int64(durationMs)
		entry.Success = success == 1
		entry.Error = errStr

		history = append(history, entry)
	}

	return history, nil
}

// SaveSyncHistory saves a sync operation to history
func (r *CrowdSecBlocklistRepository) SaveSyncHistory(ctx context.Context, entry *crowdsec.SyncHistoryEntry) error {
	success := uint8(0)
	if entry.Success {
		success = 1
	}

	query := `
		INSERT INTO vigilance_x.crowdsec_sync_history (
			blocklist_id,
			blocklist_name,
			ips_downloaded,
			ips_added,
			ips_removed,
			duration_ms,
			success,
			error
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	err := r.conn.Exec(ctx, query,
		entry.BlocklistID,
		entry.BlocklistName,
		entry.IPsDownloaded,
		entry.IPsAdded,
		entry.IPsRemoved,
		entry.DurationMs,
		success,
		entry.Error,
	)

	if err != nil {
		slog.Error("[CROWDSEC_REPO] SaveSyncHistory failed", "error", err)
		return fmt.Errorf("save sync history: %w", err)
	}

	slog.Debug("[CROWDSEC_REPO] SaveSyncHistory succeeded",
		"blocklist", entry.BlocklistName,
		"success", entry.Success)

	return nil
}

// UpdateLastSync updates the last sync timestamp and total IPs in config
func (r *CrowdSecBlocklistRepository) UpdateLastSync(ctx context.Context, totalIPs int) error {
	config, err := r.GetConfig(ctx)
	if err != nil {
		return err
	}

	config.LastSync = time.Now()
	config.TotalIPs = totalIPs

	return r.SaveConfig(ctx, config)
}

// GetSyncedIPsByBlocklist returns IPs for a specific blocklist
func (r *CrowdSecBlocklistRepository) GetSyncedIPsByBlocklist(ctx context.Context, blocklistID string) ([]string, error) {
	query := `
		SELECT ip
		FROM vigilance_x.crowdsec_synced_ips
		FINAL
		WHERE blocklist_id = ?
	`

	rows, err := r.conn.Query(ctx, query, blocklistID)
	if err != nil {
		return nil, fmt.Errorf("query synced ips by blocklist: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// ClearSyncedIPs removes all synced IPs for a blocklist
func (r *CrowdSecBlocklistRepository) ClearSyncedIPs(ctx context.Context, blocklistID string) error {
	query := `ALTER TABLE vigilance_x.crowdsec_synced_ips DELETE WHERE blocklist_id = ?`
	return r.conn.Exec(ctx, query, blocklistID)
}
