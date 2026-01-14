package clickhouse

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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
			sync_interval_minutes,
			last_sync,
			total_ips,
			total_blocklists,
			use_proxy,
			proxy_server_url
		FROM vigilance_x.crowdsec_blocklist_config
		WHERE id = 1
		ORDER BY version DESC
		LIMIT 1
	`

	var apiKey string
	var enabled uint8
	var syncInterval uint16
	var lastSync time.Time
	var totalIPs, totalBlocklists uint32
	var useProxy uint8
	var proxyServerURL string

	row := r.conn.QueryRow(ctx, query)
	err := row.Scan(
		&apiKey,
		&enabled,
		&syncInterval,
		&lastSync,
		&totalIPs,
		&totalBlocklists,
		&useProxy,
		&proxyServerURL,
	)

	if err != nil {
		slog.Warn("[CROWDSEC_REPO] GetConfig query failed, returning default", "error", err)
		return &crowdsec.BlocklistConfig{
			Enabled:             false,
			UseProxy:            false,
			SyncIntervalMinutes: 120,
		}, nil
	}

	config := &crowdsec.BlocklistConfig{
		APIKey:              apiKey,
		Enabled:             enabled == 1,
		UseProxy:            useProxy == 1,
		ProxyServerURL:      proxyServerURL,
		SyncIntervalMinutes: int(syncInterval),
		LastSync:            lastSync,
		TotalIPs:            int(totalIPs),
		TotalBlocklists:     int(totalBlocklists),
	}

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

	useProxy := uint8(0)
	if config.UseProxy {
		useProxy = 1
	}

	query := `
		INSERT INTO vigilance_x.crowdsec_blocklist_config (
			id,
			api_key,
			enabled,
			sync_interval_minutes,
			last_sync,
			total_ips,
			total_blocklists,
			use_proxy,
			proxy_server_url,
			updated_at,
			version
		) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, now(), ?)
	`

	err := r.conn.Exec(ctx, query,
		config.APIKey,
		enabled,
		config.SyncIntervalMinutes,
		config.LastSync,
		config.TotalIPs,
		config.TotalBlocklists,
		useProxy,
		config.ProxyServerURL,
		currentVersion+1,
	)

	if err != nil {
		slog.Error("[CROWDSEC_REPO] SaveConfig failed", "error", err)
		return fmt.Errorf("save crowdsec config: %w", err)
	}

	return nil
}

// GetIPsForBlocklist returns all IPs for a specific blocklist
func (r *CrowdSecBlocklistRepository) GetIPsForBlocklist(ctx context.Context, blocklistID string) ([]string, error) {
	query := `
		SELECT ip
		FROM vigilance_x.crowdsec_blocklist_ips
		FINAL
		WHERE blocklist_id = ?
	`

	rows, err := r.conn.Query(ctx, query, blocklistID)
	if err != nil {
		return nil, fmt.Errorf("query IPs for blocklist: %w", err)
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

// GetAllIPs returns all IPs from all blocklists
func (r *CrowdSecBlocklistRepository) GetAllIPs(ctx context.Context) ([]crowdsec.BlocklistIP, error) {
	query := `
		SELECT
			ip,
			blocklist_id,
			blocklist_label,
			first_seen,
			last_seen,
			country_code
		FROM vigilance_x.crowdsec_blocklist_ips
		FINAL
		ORDER BY blocklist_id, ip
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query all IPs: %w", err)
	}
	defer rows.Close()

	var result []crowdsec.BlocklistIP
	for rows.Next() {
		var ip crowdsec.BlocklistIP
		if err := rows.Scan(&ip.IP, &ip.BlocklistID, &ip.BlocklistLabel, &ip.FirstSeen, &ip.LastSeen, &ip.CountryCode); err != nil {
			slog.Warn("[CROWDSEC_REPO] Failed to scan IP row", "error", err)
			continue
		}
		result = append(result, ip)
	}

	return result, nil
}

// AddIPs adds new IPs to the database
func (r *CrowdSecBlocklistRepository) AddIPs(ctx context.Context, ips []crowdsec.BlocklistIP) error {
	if len(ips) == 0 {
		return nil
	}

	// Get max version for these IPs
	var maxVersion uint64
	row := r.conn.QueryRow(ctx, "SELECT max(version) FROM vigilance_x.crowdsec_blocklist_ips")
	if err := row.Scan(&maxVersion); err != nil {
		maxVersion = 0
	}
	newVersion := maxVersion + 1

	batch, err := r.conn.PrepareBatch(ctx, `
		INSERT INTO vigilance_x.crowdsec_blocklist_ips (ip, blocklist_id, blocklist_label, first_seen, last_seen, country_code, version)
	`)
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}

	for _, ip := range ips {
		if err := batch.Append(ip.IP, ip.BlocklistID, ip.BlocklistLabel, ip.FirstSeen, ip.LastSeen, ip.CountryCode, newVersion); err != nil {
			slog.Warn("[CROWDSEC_REPO] Failed to append IP to batch", "ip", ip.IP, "error", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("send batch: %w", err)
	}

	slog.Info("[CROWDSEC_REPO] Added IPs", "count", len(ips))
	return nil
}

// RemoveIPs removes IPs from a blocklist using lightweight delete
func (r *CrowdSecBlocklistRepository) RemoveIPs(ctx context.Context, blocklistID string, ips []string) error {
	if len(ips) == 0 {
		return nil
	}

	// Use ALTER TABLE DELETE for lightweight delete
	// Build the IN clause
	for _, ip := range ips {
		query := `ALTER TABLE vigilance_x.crowdsec_blocklist_ips DELETE WHERE blocklist_id = ? AND ip = ?`
		if err := r.conn.Exec(ctx, query, blocklistID, ip); err != nil {
			slog.Warn("[CROWDSEC_REPO] Failed to delete IP", "ip", ip, "error", err)
		}
	}

	slog.Info("[CROWDSEC_REPO] Removed IPs", "blocklist_id", blocklistID, "count", len(ips))
	return nil
}

// ClearBlocklist removes all IPs for a specific blocklist
func (r *CrowdSecBlocklistRepository) ClearBlocklist(ctx context.Context, blocklistID string) error {
	query := `ALTER TABLE vigilance_x.crowdsec_blocklist_ips DELETE WHERE blocklist_id = ?`
	if err := r.conn.Exec(ctx, query, blocklistID); err != nil {
		return fmt.Errorf("clear blocklist: %w", err)
	}

	slog.Info("[CROWDSEC_REPO] Cleared blocklist", "blocklist_id", blocklistID)
	return nil
}

// ClearAllIPs removes all IPs from all blocklists
func (r *CrowdSecBlocklistRepository) ClearAllIPs(ctx context.Context) error {
	query := `TRUNCATE TABLE vigilance_x.crowdsec_blocklist_ips`
	if err := r.conn.Exec(ctx, query); err != nil {
		return fmt.Errorf("clear all IPs: %w", err)
	}

	slog.Info("[CROWDSEC_REPO] Cleared all IPs")
	return nil
}

// GetSyncHistory returns recent sync history
func (r *CrowdSecBlocklistRepository) GetSyncHistory(ctx context.Context, limit int) ([]crowdsec.SyncHistoryEntry, error) {
	query := `
		SELECT
			id,
			timestamp,
			blocklist_id,
			blocklist_label,
			ips_in_file,
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
		var ipsInFile, ipsAdded, ipsRemoved, durationMs uint32
		var success uint8
		var errStr string

		err := rows.Scan(
			&id,
			&entry.Timestamp,
			&entry.BlocklistID,
			&entry.BlocklistLabel,
			&ipsInFile,
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
		entry.IPsInFile = int(ipsInFile)
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
			blocklist_label,
			ips_in_file,
			ips_added,
			ips_removed,
			duration_ms,
			success,
			error
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	err := r.conn.Exec(ctx, query,
		entry.BlocklistID,
		entry.BlocklistLabel,
		entry.IPsInFile,
		entry.IPsAdded,
		entry.IPsRemoved,
		entry.DurationMs,
		success,
		entry.Error,
	)

	if err != nil {
		return fmt.Errorf("save sync history: %w", err)
	}

	return nil
}

// GetStats returns total IPs and blocklists count
func (r *CrowdSecBlocklistRepository) GetStats(ctx context.Context) (totalIPs int, totalBlocklists int, err error) {
	// Count total unique IPs
	row := r.conn.QueryRow(ctx, `SELECT count(DISTINCT ip) FROM vigilance_x.crowdsec_blocklist_ips FINAL`)
	var ips uint64
	if err := row.Scan(&ips); err != nil {
		return 0, 0, err
	}

	// Count total blocklists
	row = r.conn.QueryRow(ctx, `SELECT count(DISTINCT blocklist_id) FROM vigilance_x.crowdsec_blocklist_ips FINAL`)
	var lists uint64
	if err := row.Scan(&lists); err != nil {
		return int(ips), 0, err
	}

	return int(ips), int(lists), nil
}

// IPListQuery represents query parameters for listing IPs
type IPListQuery struct {
	Page        int
	PageSize    int
	Search      string
	Country     string // Filter by country code (enriched at query time, not stored)
	BlocklistID string
}

// IPListResult represents the paginated result
type IPListResult struct {
	IPs        []crowdsec.BlocklistIP
	Total      int
	Page       int
	PageSize   int
	TotalPages int
}

// GetIPsPaginated returns IPs with pagination, search, and filtering
func (r *CrowdSecBlocklistRepository) GetIPsPaginated(ctx context.Context, query IPListQuery) (*IPListResult, error) {
	// Default values
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PageSize < 1 || query.PageSize > 100 {
		query.PageSize = 50
	}

	offset := (query.Page - 1) * query.PageSize

	// Build WHERE clause
	var conditions []string
	var args []interface{}

	if query.Search != "" {
		conditions = append(conditions, "ip LIKE ?")
		args = append(args, "%"+query.Search+"%")
	}
	if query.BlocklistID != "" {
		conditions = append(conditions, "blocklist_id = ?")
		args = append(args, query.BlocklistID)
	}
	if query.Country != "" {
		conditions = append(conditions, "country_code = ?")
		args = append(args, query.Country)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`
		SELECT count()
		FROM vigilance_x.crowdsec_blocklist_ips
		FINAL
		%s
	`, whereClause)

	var total uint64
	row := r.conn.QueryRow(ctx, countQuery, args...)
	if err := row.Scan(&total); err != nil {
		return nil, fmt.Errorf("count IPs: %w", err)
	}

	// Get paginated results
	dataQuery := fmt.Sprintf(`
		SELECT
			ip,
			blocklist_id,
			blocklist_label,
			first_seen,
			last_seen,
			country_code
		FROM vigilance_x.crowdsec_blocklist_ips
		FINAL
		%s
		ORDER BY blocklist_label, ip
		LIMIT ? OFFSET ?
	`, whereClause)

	args = append(args, query.PageSize, offset)

	rows, err := r.conn.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query IPs: %w", err)
	}
	defer rows.Close()

	var ips []crowdsec.BlocklistIP
	for rows.Next() {
		var ip crowdsec.BlocklistIP
		if err := rows.Scan(&ip.IP, &ip.BlocklistID, &ip.BlocklistLabel, &ip.FirstSeen, &ip.LastSeen, &ip.CountryCode); err != nil {
			slog.Warn("[CROWDSEC_REPO] Failed to scan IP row", "error", err)
			continue
		}
		ips = append(ips, ip)
	}

	totalPages := int(total) / query.PageSize
	if int(total)%query.PageSize > 0 {
		totalPages++
	}

	return &IPListResult{
		IPs:        ips,
		Total:      int(total),
		Page:       query.Page,
		PageSize:   query.PageSize,
		TotalPages: totalPages,
	}, nil
}

// GetBlocklistSummary returns summary of each blocklist (name + IP count)
func (r *CrowdSecBlocklistRepository) GetBlocklistSummary(ctx context.Context) ([]map[string]interface{}, error) {
	query := `
		SELECT
			blocklist_id,
			blocklist_label,
			count() as ip_count
		FROM vigilance_x.crowdsec_blocklist_ips
		FINAL
		GROUP BY blocklist_id, blocklist_label
		ORDER BY ip_count DESC
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query blocklist summary: %w", err)
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var id, label string
		var count uint64
		if err := rows.Scan(&id, &label, &count); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"id":       id,
			"label":    label,
			"ip_count": count,
		})
	}

	return result, nil
}

// GetUniqueCountries returns all unique country codes from the blocklist IPs
func (r *CrowdSecBlocklistRepository) GetUniqueCountries(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT country_code
		FROM vigilance_x.crowdsec_blocklist_ips
		FINAL
		WHERE country_code != ''
		ORDER BY country_code
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query unique countries: %w", err)
	}
	defer rows.Close()

	var countries []string
	for rows.Next() {
		var country string
		if err := rows.Scan(&country); err != nil {
			continue
		}
		countries = append(countries, country)
	}

	return countries, nil
}

// GetExistingBlocklistIDs returns all unique blocklist IDs from the database
func (r *CrowdSecBlocklistRepository) GetExistingBlocklistIDs(ctx context.Context) ([]struct {
	ID    string
	Label string
}, error) {
	query := `
		SELECT DISTINCT blocklist_id, blocklist_label
		FROM vigilance_x.crowdsec_blocklist_ips
		FINAL
		WHERE blocklist_id != ''
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query existing blocklist IDs: %w", err)
	}
	defer rows.Close()

	var blocklists []struct {
		ID    string
		Label string
	}
	for rows.Next() {
		var bl struct {
			ID    string
			Label string
		}
		if err := rows.Scan(&bl.ID, &bl.Label); err != nil {
			continue
		}
		blocklists = append(blocklists, bl)
	}

	return blocklists, nil
}

// GetIPsWithoutCountry returns IPs that don't have country_code set
func (r *CrowdSecBlocklistRepository) GetIPsWithoutCountry(ctx context.Context, limit int) ([]string, error) {
	query := `
		SELECT ip
		FROM vigilance_x.crowdsec_blocklist_ips
		FINAL
		WHERE country_code = ''
		LIMIT ?
	`

	rows, err := r.conn.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query IPs without country: %w", err)
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

// UpdateIPCountry updates the country_code for an IP using INSERT with new version
func (r *CrowdSecBlocklistRepository) UpdateIPCountry(ctx context.Context, ip, countryCode string) error {
	// Get current data for this IP
	query := `
		SELECT blocklist_id, blocklist_label, first_seen, last_seen, version
		FROM vigilance_x.crowdsec_blocklist_ips
		FINAL
		WHERE ip = ?
		LIMIT 1
	`

	var blocklistID, blocklistLabel string
	var firstSeen, lastSeen time.Time
	var version uint64

	row := r.conn.QueryRow(ctx, query, ip)
	if err := row.Scan(&blocklistID, &blocklistLabel, &firstSeen, &lastSeen, &version); err != nil {
		return fmt.Errorf("get IP data: %w", err)
	}

	// Insert updated row with new version
	insertQuery := `
		INSERT INTO vigilance_x.crowdsec_blocklist_ips
		(ip, blocklist_id, blocklist_label, first_seen, last_seen, country_code, version)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	if err := r.conn.Exec(ctx, insertQuery, ip, blocklistID, blocklistLabel, firstSeen, lastSeen, countryCode, version+1); err != nil {
		return fmt.Errorf("update IP country: %w", err)
	}

	return nil
}
