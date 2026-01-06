package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// BansRepository handles ban data persistence in ClickHouse
type BansRepository struct {
	conn *Connection
}

// NewBansRepository creates a new bans repository
func NewBansRepository(conn *Connection) *BansRepository {
	return &BansRepository{conn: conn}
}

// GetActiveBans retrieves all currently active bans
func (r *BansRepository) GetActiveBans(ctx context.Context) ([]entity.BanStatus, error) {
	query := `
		SELECT
			ip,
			status,
			ban_count,
			first_ban,
			last_ban,
			expires_at,
			reason,
			source,
			synced_xgs,
			updated_at
		FROM ip_ban_status FINAL
		WHERE status IN ('active', 'permanent')
		ORDER BY last_ban DESC
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query active bans: %w", err)
	}
	defer rows.Close()

	var bans []entity.BanStatus
	for rows.Next() {
		var ban entity.BanStatus
		var expiresAt *time.Time

		if err := rows.Scan(
			&ban.IP,
			&ban.Status,
			&ban.BanCount,
			&ban.FirstBan,
			&ban.LastBan,
			&expiresAt,
			&ban.Reason,
			&ban.Source,
			&ban.SyncedXGS,
			&ban.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan ban row: %w", err)
		}

		if expiresAt != nil {
			ban.ExpiresAt = expiresAt
		}

		bans = append(bans, ban)
	}

	return bans, nil
}

// GetBanByIP retrieves a specific ban by IP address
func (r *BansRepository) GetBanByIP(ctx context.Context, ip string) (*entity.BanStatus, error) {
	query := `
		SELECT
			ip,
			status,
			ban_count,
			first_ban,
			last_ban,
			expires_at,
			reason,
			source,
			synced_xgs,
			updated_at
		FROM ip_ban_status FINAL
		WHERE ip = ?
		LIMIT 1
	`

	row := r.conn.DB().QueryRow(ctx, query, ip)

	var ban entity.BanStatus
	var expiresAt *time.Time

	if err := row.Scan(
		&ban.IP,
		&ban.Status,
		&ban.BanCount,
		&ban.FirstBan,
		&ban.LastBan,
		&expiresAt,
		&ban.Reason,
		&ban.Source,
		&ban.SyncedXGS,
		&ban.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("scan ban: %w", err)
	}

	if expiresAt != nil {
		ban.ExpiresAt = expiresAt
	}

	return &ban, nil
}

// UpsertBan creates or updates a ban status
func (r *BansRepository) UpsertBan(ctx context.Context, ban *entity.BanStatus) error {
	query := `
		INSERT INTO ip_ban_status (
			ip, status, ban_count, first_ban, last_ban,
			expires_at, reason, source, synced_xgs, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var expiresAt time.Time
	if ban.ExpiresAt != nil {
		expiresAt = *ban.ExpiresAt
	}

	if err := r.conn.DB().Exec(ctx, query,
		ban.IP,
		ban.Status,
		ban.BanCount,
		ban.FirstBan,
		ban.LastBan,
		expiresAt,
		ban.Reason,
		ban.Source,
		ban.SyncedXGS,
		time.Now(),
	); err != nil {
		return fmt.Errorf("upsert ban: %w", err)
	}

	return nil
}

// UpdateSyncStatus updates the XGS sync status for a ban
func (r *BansRepository) UpdateSyncStatus(ctx context.Context, ip string, synced bool) error {
	// Get current ban
	ban, err := r.GetBanByIP(ctx, ip)
	if err != nil {
		return fmt.Errorf("get ban for sync update: %w", err)
	}

	ban.SyncedXGS = synced
	return r.UpsertBan(ctx, ban)
}

// RecordBanHistory records a ban action in the history table
func (r *BansRepository) RecordBanHistory(ctx context.Context, history *entity.BanHistory) error {
	query := `
		INSERT INTO ban_history (
			ip, action, reason, duration_hours, source,
			performed_by, synced_xgs, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	if err := r.conn.DB().Exec(ctx, query,
		history.IP,
		history.Action,
		history.Reason,
		history.DurationHours,
		history.Source,
		history.PerformedBy,
		history.SyncedXGS,
		time.Now(),
	); err != nil {
		return fmt.Errorf("record ban history: %w", err)
	}

	return nil
}

// GetBanHistory retrieves ban history for an IP
func (r *BansRepository) GetBanHistory(ctx context.Context, ip string, limit int) ([]entity.BanHistory, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT
			ip, action, reason, duration_hours, source,
			performed_by, synced_xgs, created_at
		FROM ban_history
		WHERE ip = ?
		ORDER BY created_at DESC
		LIMIT ?
	`

	rows, err := r.conn.DB().Query(ctx, query, ip, limit)
	if err != nil {
		return nil, fmt.Errorf("query ban history: %w", err)
	}
	defer rows.Close()

	var history []entity.BanHistory
	for rows.Next() {
		var h entity.BanHistory
		if err := rows.Scan(
			&h.IP,
			&h.Action,
			&h.Reason,
			&h.DurationHours,
			&h.Source,
			&h.PerformedBy,
			&h.SyncedXGS,
			&h.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan history row: %w", err)
		}
		history = append(history, h)
	}

	return history, nil
}

// GetBanStats retrieves ban statistics
func (r *BansRepository) GetBanStats(ctx context.Context) (*entity.BanStats, error) {
	stats := &entity.BanStats{}

	// Total active bans
	query := `
		SELECT count() as cnt
		FROM ip_ban_status FINAL
		WHERE status IN ('active', 'permanent')
	`
	if err := r.conn.DB().QueryRow(ctx, query).Scan(&stats.TotalActiveBans); err != nil {
		return nil, fmt.Errorf("count active bans: %w", err)
	}

	// Total permanent bans
	query = `
		SELECT count() as cnt
		FROM ip_ban_status FINAL
		WHERE status = 'permanent'
	`
	if err := r.conn.DB().QueryRow(ctx, query).Scan(&stats.TotalPermanentBans); err != nil {
		return nil, fmt.Errorf("count permanent bans: %w", err)
	}

	// Bans in last 24h
	query = `
		SELECT count() as cnt
		FROM ban_history
		WHERE action = 'ban' AND created_at >= now() - INTERVAL 24 HOUR
	`
	if err := r.conn.DB().QueryRow(ctx, query).Scan(&stats.BansLast24h); err != nil {
		return nil, fmt.Errorf("count 24h bans: %w", err)
	}

	// Recidivist IPs (banned 3+ times)
	query = `
		SELECT count() as cnt
		FROM ip_ban_status FINAL
		WHERE ban_count >= 3
	`
	if err := r.conn.DB().QueryRow(ctx, query).Scan(&stats.RecidivistIPs); err != nil {
		return nil, fmt.Errorf("count recidivists: %w", err)
	}

	// Pending sync
	query = `
		SELECT count() as cnt
		FROM ip_ban_status FINAL
		WHERE status IN ('active', 'permanent') AND synced_xgs = false
	`
	if err := r.conn.DB().QueryRow(ctx, query).Scan(&stats.PendingSync); err != nil {
		return nil, fmt.Errorf("count pending sync: %w", err)
	}

	return stats, nil
}

// GetExpiredBans retrieves bans that have expired but are still marked active
func (r *BansRepository) GetExpiredBans(ctx context.Context) ([]entity.BanStatus, error) {
	query := `
		SELECT
			ip,
			status,
			ban_count,
			first_ban,
			last_ban,
			expires_at,
			reason,
			source,
			synced_xgs,
			updated_at
		FROM ip_ban_status FINAL
		WHERE status = 'active'
		  AND expires_at < now()
		  AND expires_at > toDateTime('1970-01-01')
		ORDER BY expires_at ASC
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query expired bans: %w", err)
	}
	defer rows.Close()

	var bans []entity.BanStatus
	for rows.Next() {
		var ban entity.BanStatus
		var expiresAt *time.Time

		if err := rows.Scan(
			&ban.IP,
			&ban.Status,
			&ban.BanCount,
			&ban.FirstBan,
			&ban.LastBan,
			&expiresAt,
			&ban.Reason,
			&ban.Source,
			&ban.SyncedXGS,
			&ban.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan expired ban: %w", err)
		}

		if expiresAt != nil {
			ban.ExpiresAt = expiresAt
		}

		bans = append(bans, ban)
	}

	return bans, nil
}

// GetUnsyncedBans retrieves bans that need to be synced to XGS
func (r *BansRepository) GetUnsyncedBans(ctx context.Context) ([]entity.BanStatus, error) {
	query := `
		SELECT
			ip,
			status,
			ban_count,
			first_ban,
			last_ban,
			expires_at,
			reason,
			source,
			synced_xgs,
			updated_at
		FROM ip_ban_status FINAL
		WHERE status IN ('active', 'permanent') AND synced_xgs = false
		ORDER BY last_ban DESC
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query unsynced bans: %w", err)
	}
	defer rows.Close()

	var bans []entity.BanStatus
	for rows.Next() {
		var ban entity.BanStatus
		var expiresAt *time.Time

		if err := rows.Scan(
			&ban.IP,
			&ban.Status,
			&ban.BanCount,
			&ban.FirstBan,
			&ban.LastBan,
			&expiresAt,
			&ban.Reason,
			&ban.Source,
			&ban.SyncedXGS,
			&ban.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan unsynced ban: %w", err)
		}

		if expiresAt != nil {
			ban.ExpiresAt = expiresAt
		}

		bans = append(bans, ban)
	}

	return bans, nil
}

// IsWhitelisted checks if an IP is in the whitelist
func (r *BansRepository) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	query := `
		SELECT count() > 0
		FROM ip_whitelist FINAL
		WHERE ip = ? AND active = true
	`

	var whitelisted bool
	if err := r.conn.DB().QueryRow(ctx, query, ip).Scan(&whitelisted); err != nil {
		return false, fmt.Errorf("check whitelist: %w", err)
	}

	return whitelisted, nil
}

// GetWhitelist retrieves all whitelisted IPs
func (r *BansRepository) GetWhitelist(ctx context.Context) ([]entity.WhitelistEntry, error) {
	query := `
		SELECT ip, reason, added_by, created_at
		FROM ip_whitelist FINAL
		WHERE active = true
		ORDER BY created_at DESC
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query whitelist: %w", err)
	}
	defer rows.Close()

	var entries []entity.WhitelistEntry
	for rows.Next() {
		var e entity.WhitelistEntry
		if err := rows.Scan(&e.IP, &e.Reason, &e.AddedBy, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan whitelist entry: %w", err)
		}
		entries = append(entries, e)
	}

	return entries, nil
}

// AddToWhitelist adds an IP to the whitelist
func (r *BansRepository) AddToWhitelist(ctx context.Context, entry *entity.WhitelistEntry) error {
	query := `
		INSERT INTO ip_whitelist (ip, reason, added_by, active, created_at)
		VALUES (?, ?, ?, true, ?)
	`

	if err := r.conn.DB().Exec(ctx, query,
		entry.IP,
		entry.Reason,
		entry.AddedBy,
		time.Now(),
	); err != nil {
		return fmt.Errorf("add to whitelist: %w", err)
	}

	return nil
}

// RemoveFromWhitelist removes an IP from the whitelist
func (r *BansRepository) RemoveFromWhitelist(ctx context.Context, ip string) error {
	query := `
		INSERT INTO ip_whitelist (ip, reason, added_by, active, created_at)
		SELECT ip, reason, added_by, false, now()
		FROM ip_whitelist FINAL
		WHERE ip = ?
	`

	if err := r.conn.DB().Exec(ctx, query, ip); err != nil {
		return fmt.Errorf("remove from whitelist: %w", err)
	}

	return nil
}
