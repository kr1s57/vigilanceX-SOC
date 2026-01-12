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
			immune_until,
			updated_at
		FROM ip_ban_status FINAL
		WHERE ip = ?
		LIMIT 1
	`

	row := r.conn.DB().QueryRow(ctx, query, ip)

	var ban entity.BanStatus
	var expiresAt *time.Time
	var immuneUntil *time.Time

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
		&immuneUntil,
		&ban.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("scan ban: %w", err)
	}

	if expiresAt != nil {
		ban.ExpiresAt = expiresAt
	}
	if immuneUntil != nil && !immuneUntil.IsZero() && immuneUntil.Year() > 1970 {
		ban.ImmuneUntil = immuneUntil
	}

	return &ban, nil
}

// IsIPImmune checks if an IP has active immunity from auto-ban
func (r *BansRepository) IsIPImmune(ctx context.Context, ip string) (bool, *time.Time, error) {
	query := `
		SELECT immune_until
		FROM ip_ban_status FINAL
		WHERE ip = ?
		LIMIT 1
	`

	var immuneUntil *time.Time
	if err := r.conn.DB().QueryRow(ctx, query, ip).Scan(&immuneUntil); err != nil {
		return false, nil, nil // No record = not immune
	}

	if immuneUntil == nil || immuneUntil.IsZero() || immuneUntil.Year() <= 1970 {
		return false, nil, nil
	}

	if time.Now().Before(*immuneUntil) {
		return true, immuneUntil, nil
	}

	return false, nil, nil
}

// UpsertBan creates or updates a ban status
func (r *BansRepository) UpsertBan(ctx context.Context, ban *entity.BanStatus) error {
	query := `
		INSERT INTO ip_ban_status (
			ip, status, ban_count, first_ban, last_ban,
			expires_at, reason, source, synced_xgs, immune_until, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var expiresAt time.Time
	if ban.ExpiresAt != nil {
		expiresAt = *ban.ExpiresAt
	}

	var immuneUntil time.Time
	if ban.ImmuneUntil != nil {
		immuneUntil = *ban.ImmuneUntil
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
		immuneUntil,
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

// IsWhitelisted checks if an IP is in the whitelist (legacy - returns simple boolean)
func (r *BansRepository) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	query := `
		SELECT count() > 0
		FROM ip_whitelist_v2 FINAL
		WHERE ip = toIPv4(?)
		  AND is_active = 1
		  AND (expires_at = toDateTime(0) OR expires_at > now())
	`

	var whitelisted bool
	if err := r.conn.DB().QueryRow(ctx, query, ip).Scan(&whitelisted); err != nil {
		return false, fmt.Errorf("check whitelist: %w", err)
	}

	return whitelisted, nil
}

// CheckWhitelistV2 performs a full whitelist check with soft whitelist support (v2.0)
func (r *BansRepository) CheckWhitelistV2(ctx context.Context, ip string) (*entity.WhitelistCheckResult, error) {
	query := `
		SELECT
			toString(ip) as ip_str,
			cidr_mask,
			type,
			reason,
			description,
			score_modifier,
			alert_only,
			expires_at,
			tags,
			added_by,
			is_active,
			created_at
		FROM ip_whitelist_v2 FINAL
		WHERE ip = toIPv4(?)
		  AND is_active = 1
		  AND (expires_at = toDateTime(0) OR expires_at > now())
		LIMIT 1
	`

	row := r.conn.DB().QueryRow(ctx, query, ip)

	var entry entity.WhitelistEntry
	var expiresAt time.Time
	var alertOnly uint8
	var isActive uint8

	err := row.Scan(
		&entry.IP,
		&entry.CIDRMask,
		&entry.Type,
		&entry.Reason,
		&entry.Description,
		&entry.ScoreModifier,
		&alertOnly,
		&expiresAt,
		&entry.Tags,
		&entry.AddedBy,
		&isActive,
		&entry.CreatedAt,
	)

	if err != nil {
		// No entry found = not whitelisted
		return &entity.WhitelistCheckResult{
			IsWhitelisted: false,
			EffectiveType: "none",
			ScoreModifier: 0,
			AllowAutoBan:  true,
			AlertRequired: false,
		}, nil
	}

	entry.AlertOnly = alertOnly == 1
	entry.IsActive = isActive == 1
	if !expiresAt.IsZero() && expiresAt.Year() > 1970 {
		entry.ExpiresAt = &expiresAt
	}

	return entry.CheckWhitelist(), nil
}

// GetWhitelist retrieves all whitelisted IPs (v2.0 with soft whitelist)
func (r *BansRepository) GetWhitelist(ctx context.Context) ([]entity.WhitelistEntry, error) {
	query := `
		SELECT
			toString(ip) as ip_str,
			cidr_mask,
			type,
			reason,
			description,
			score_modifier,
			alert_only,
			expires_at,
			tags,
			added_by,
			is_active,
			created_at
		FROM ip_whitelist_v2 FINAL
		WHERE is_active = 1
		ORDER BY type, created_at DESC
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query whitelist: %w", err)
	}
	defer rows.Close()

	var entries []entity.WhitelistEntry
	for rows.Next() {
		var e entity.WhitelistEntry
		var expiresAt time.Time
		var alertOnly uint8
		var isActive uint8

		if err := rows.Scan(
			&e.IP,
			&e.CIDRMask,
			&e.Type,
			&e.Reason,
			&e.Description,
			&e.ScoreModifier,
			&alertOnly,
			&expiresAt,
			&e.Tags,
			&e.AddedBy,
			&isActive,
			&e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan whitelist entry: %w", err)
		}

		e.AlertOnly = alertOnly == 1
		e.IsActive = isActive == 1
		if !expiresAt.IsZero() && expiresAt.Year() > 1970 {
			e.ExpiresAt = &expiresAt
		}

		entries = append(entries, e)
	}

	return entries, nil
}

// GetWhitelistByType retrieves whitelist entries filtered by type (v2.0)
func (r *BansRepository) GetWhitelistByType(ctx context.Context, whitelistType string) ([]entity.WhitelistEntry, error) {
	query := `
		SELECT
			toString(ip) as ip_str,
			cidr_mask,
			type,
			reason,
			description,
			score_modifier,
			alert_only,
			expires_at,
			tags,
			added_by,
			is_active,
			created_at
		FROM ip_whitelist_v2 FINAL
		WHERE is_active = 1 AND type = ?
		ORDER BY created_at DESC
	`

	rows, err := r.conn.DB().Query(ctx, query, whitelistType)
	if err != nil {
		return nil, fmt.Errorf("query whitelist by type: %w", err)
	}
	defer rows.Close()

	var entries []entity.WhitelistEntry
	for rows.Next() {
		var e entity.WhitelistEntry
		var expiresAt time.Time
		var alertOnly uint8
		var isActive uint8

		if err := rows.Scan(
			&e.IP,
			&e.CIDRMask,
			&e.Type,
			&e.Reason,
			&e.Description,
			&e.ScoreModifier,
			&alertOnly,
			&expiresAt,
			&e.Tags,
			&e.AddedBy,
			&isActive,
			&e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan whitelist entry: %w", err)
		}

		e.AlertOnly = alertOnly == 1
		e.IsActive = isActive == 1
		if !expiresAt.IsZero() && expiresAt.Year() > 1970 {
			e.ExpiresAt = &expiresAt
		}

		entries = append(entries, e)
	}

	return entries, nil
}

// AddToWhitelist adds an IP to the whitelist (v2.0 with soft whitelist support)
func (r *BansRepository) AddToWhitelist(ctx context.Context, entry *entity.WhitelistEntry) error {
	// Set defaults
	if entry.Type == "" {
		entry.Type = entity.WhitelistTypeHard
	}
	if entry.ScoreModifier == 0 && entry.Type == entity.WhitelistTypeSoft {
		entry.ScoreModifier = 50 // Default 50% reduction
	}
	if entry.CIDRMask == 0 {
		entry.CIDRMask = 32 // Single IP
	}

	var expiresAt time.Time
	if entry.ExpiresAt != nil {
		expiresAt = *entry.ExpiresAt
	}

	alertOnly := uint8(0)
	if entry.AlertOnly {
		alertOnly = 1
	}

	query := `
		INSERT INTO ip_whitelist_v2 (
			ip, cidr_mask, type, reason, description,
			score_modifier, alert_only, expires_at, tags,
			added_by, is_active, created_at, version
		) VALUES (
			toIPv4(?), ?, ?, ?, ?,
			?, ?, ?, ?,
			?, 1, now(), toUnixTimestamp(now())
		)
	`

	if err := r.conn.DB().Exec(ctx, query,
		entry.IP,
		entry.CIDRMask,
		entry.Type,
		entry.Reason,
		entry.Description,
		entry.ScoreModifier,
		alertOnly,
		expiresAt,
		entry.Tags,
		entry.AddedBy,
	); err != nil {
		return fmt.Errorf("add to whitelist: %w", err)
	}

	return nil
}

// UpdateWhitelistEntry updates an existing whitelist entry (v2.0)
func (r *BansRepository) UpdateWhitelistEntry(ctx context.Context, entry *entity.WhitelistEntry) error {
	var expiresAt time.Time
	if entry.ExpiresAt != nil {
		expiresAt = *entry.ExpiresAt
	}

	alertOnly := uint8(0)
	if entry.AlertOnly {
		alertOnly = 1
	}

	isActive := uint8(0)
	if entry.IsActive {
		isActive = 1
	}

	query := `
		INSERT INTO ip_whitelist_v2 (
			ip, cidr_mask, type, reason, description,
			score_modifier, alert_only, expires_at, tags,
			added_by, is_active, created_at, version
		) VALUES (
			toIPv4(?), ?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, now(), toUnixTimestamp(now())
		)
	`

	if err := r.conn.DB().Exec(ctx, query,
		entry.IP,
		entry.CIDRMask,
		entry.Type,
		entry.Reason,
		entry.Description,
		entry.ScoreModifier,
		alertOnly,
		expiresAt,
		entry.Tags,
		entry.AddedBy,
		isActive,
	); err != nil {
		return fmt.Errorf("update whitelist entry: %w", err)
	}

	return nil
}

// RemoveFromWhitelist removes an IP from the whitelist (marks as inactive)
func (r *BansRepository) RemoveFromWhitelist(ctx context.Context, ip string) error {
	// Insert a new version with is_active = 0
	query := `
		INSERT INTO ip_whitelist_v2 (
			ip, cidr_mask, type, reason, description,
			score_modifier, alert_only, expires_at, tags,
			added_by, is_active, created_at, version
		)
		SELECT
			ip, cidr_mask, type, reason, description,
			score_modifier, alert_only, expires_at, tags,
			added_by, 0, now(), toUnixTimestamp(now())
		FROM ip_whitelist_v2 FINAL
		WHERE ip = toIPv4(?) AND is_active = 1
	`

	if err := r.conn.DB().Exec(ctx, query, ip); err != nil {
		return fmt.Errorf("remove from whitelist: %w", err)
	}

	return nil
}

// GetWhitelistStats returns whitelist statistics by type (v2.0)
func (r *BansRepository) GetWhitelistStats(ctx context.Context) (map[string]int, error) {
	query := `
		SELECT
			type,
			count() as cnt
		FROM ip_whitelist_v2 FINAL
		WHERE is_active = 1
		  AND (expires_at = toDateTime(0) OR expires_at > now())
		GROUP BY type
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query whitelist stats: %w", err)
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var whitelistType string
		var count uint64
		if err := rows.Scan(&whitelistType, &count); err != nil {
			return nil, fmt.Errorf("scan whitelist stats: %w", err)
		}
		stats[whitelistType] = int(count)
	}

	return stats, nil
}

// GetExpiredWhitelistEntries returns whitelist entries that have expired (v2.0)
func (r *BansRepository) GetExpiredWhitelistEntries(ctx context.Context) ([]entity.WhitelistEntry, error) {
	query := `
		SELECT
			toString(ip) as ip_str,
			cidr_mask,
			type,
			reason,
			description,
			score_modifier,
			alert_only,
			expires_at,
			tags,
			added_by,
			is_active,
			created_at
		FROM ip_whitelist_v2 FINAL
		WHERE is_active = 1
		  AND expires_at != toDateTime(0)
		  AND expires_at < now()
		ORDER BY expires_at ASC
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query expired whitelist: %w", err)
	}
	defer rows.Close()

	var entries []entity.WhitelistEntry
	for rows.Next() {
		var e entity.WhitelistEntry
		var expiresAt time.Time
		var alertOnly uint8
		var isActive uint8

		if err := rows.Scan(
			&e.IP,
			&e.CIDRMask,
			&e.Type,
			&e.Reason,
			&e.Description,
			&e.ScoreModifier,
			&alertOnly,
			&expiresAt,
			&e.Tags,
			&e.AddedBy,
			&isActive,
			&e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan expired whitelist entry: %w", err)
		}

		e.AlertOnly = alertOnly == 1
		e.IsActive = isActive == 1
		e.ExpiresAt = &expiresAt

		entries = append(entries, e)
	}

	return entries, nil
}
