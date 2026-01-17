package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// WAFServersRepository handles WAF monitored servers persistence in ClickHouse
type WAFServersRepository struct {
	conn *Connection
}

// NewWAFServersRepository creates a new WAF servers repository
func NewWAFServersRepository(conn *Connection) *WAFServersRepository {
	return &WAFServersRepository{conn: conn}
}

// GetAll retrieves all enabled WAF monitored servers
func (r *WAFServersRepository) GetAll(ctx context.Context) ([]entity.WAFMonitoredServer, error) {
	query := `
		SELECT
			id,
			hostname,
			display_name,
			description,
			policy_enabled,
			policy_mode,
			white_countries,
			block_countries,
			waf_threshold,
			custom_ban_reason,
			enabled,
			created_at,
			created_by,
			updated_at
		FROM waf_monitored_servers FINAL
		WHERE enabled = 1
		ORDER BY hostname ASC
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query WAF servers: %w", err)
	}
	defer rows.Close()

	var servers []entity.WAFMonitoredServer
	for rows.Next() {
		var s entity.WAFMonitoredServer
		var policyEnabled uint8
		var enabled uint8

		if err := rows.Scan(
			&s.ID,
			&s.Hostname,
			&s.DisplayName,
			&s.Description,
			&policyEnabled,
			&s.PolicyMode,
			&s.WhiteCountries,
			&s.BlockCountries,
			&s.WAFThreshold,
			&s.CustomBanReason,
			&enabled,
			&s.CreatedAt,
			&s.CreatedBy,
			&s.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan WAF server row: %w", err)
		}

		s.PolicyEnabled = policyEnabled == 1
		s.Enabled = enabled == 1
		servers = append(servers, s)
	}

	return servers, nil
}

// GetByHostname retrieves a WAF server by hostname
func (r *WAFServersRepository) GetByHostname(ctx context.Context, hostname string) (*entity.WAFMonitoredServer, error) {
	query := `
		SELECT
			id,
			hostname,
			display_name,
			description,
			policy_enabled,
			policy_mode,
			white_countries,
			block_countries,
			waf_threshold,
			custom_ban_reason,
			enabled,
			created_at,
			created_by,
			updated_at
		FROM waf_monitored_servers FINAL
		WHERE hostname = ?
		LIMIT 1
	`

	row := r.conn.DB().QueryRow(ctx, query, hostname)

	var s entity.WAFMonitoredServer
	var policyEnabled uint8
	var enabled uint8

	if err := row.Scan(
		&s.ID,
		&s.Hostname,
		&s.DisplayName,
		&s.Description,
		&policyEnabled,
		&s.PolicyMode,
		&s.WhiteCountries,
		&s.BlockCountries,
		&s.WAFThreshold,
		&s.CustomBanReason,
		&enabled,
		&s.CreatedAt,
		&s.CreatedBy,
		&s.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("scan WAF server: %w", err)
	}

	s.PolicyEnabled = policyEnabled == 1
	s.Enabled = enabled == 1

	return &s, nil
}

// Create creates a new WAF monitored server
func (r *WAFServersRepository) Create(ctx context.Context, server *entity.WAFMonitoredServer) error {
	query := `
		INSERT INTO waf_monitored_servers (
			id, hostname, display_name, description,
			policy_enabled, policy_mode, white_countries, block_countries,
			waf_threshold, custom_ban_reason, enabled,
			created_at, created_by, updated_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	policyEnabled := uint8(0)
	if server.PolicyEnabled {
		policyEnabled = 1
	}
	enabled := uint8(0)
	if server.Enabled {
		enabled = 1
	}

	// Ensure arrays are not nil
	whiteCountries := server.WhiteCountries
	if whiteCountries == nil {
		whiteCountries = []string{}
	}
	blockCountries := server.BlockCountries
	if blockCountries == nil {
		blockCountries = []string{}
	}

	if server.ID == uuid.Nil {
		server.ID = uuid.New()
	}
	if server.Version == 0 {
		server.Version = uint64(time.Now().UnixNano())
	}

	if err := r.conn.DB().Exec(ctx, query,
		server.ID,
		server.Hostname,
		server.DisplayName,
		server.Description,
		policyEnabled,
		server.PolicyMode,
		whiteCountries,
		blockCountries,
		server.WAFThreshold,
		server.CustomBanReason,
		enabled,
		server.CreatedAt,
		server.CreatedBy,
		server.UpdatedAt,
		server.Version,
	); err != nil {
		return fmt.Errorf("insert WAF server: %w", err)
	}

	return nil
}

// Update updates an existing WAF monitored server
func (r *WAFServersRepository) Update(ctx context.Context, server *entity.WAFMonitoredServer) error {
	// ReplacingMergeTree uses INSERT to update
	server.UpdatedAt = time.Now()
	server.Version = uint64(time.Now().UnixNano())
	return r.Create(ctx, server)
}

// Delete soft-deletes a WAF server by marking it as disabled
func (r *WAFServersRepository) Delete(ctx context.Context, hostname string) error {
	// Get existing server
	server, err := r.GetByHostname(ctx, hostname)
	if err != nil {
		return fmt.Errorf("get server for delete: %w", err)
	}

	server.Enabled = false
	return r.Update(ctx, server)
}

// GetHostnamesWithPolicy returns a map of hostnames to their WAF server config
// Used by D2B engine for efficient policy lookup
func (r *WAFServersRepository) GetHostnamesWithPolicy(ctx context.Context) (map[string]*entity.WAFMonitoredServer, error) {
	servers, err := r.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*entity.WAFMonitoredServer)
	for i := range servers {
		if servers[i].PolicyEnabled {
			result[servers[i].Hostname] = &servers[i]
		}
	}

	return result, nil
}

// GetAllHostnames returns just the hostnames of all configured servers
func (r *WAFServersRepository) GetAllHostnames(ctx context.Context) ([]string, error) {
	query := `
		SELECT hostname
		FROM waf_monitored_servers FINAL
		WHERE enabled = 1
		ORDER BY hostname ASC
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query hostnames: %w", err)
	}
	defer rows.Close()

	var hostnames []string
	for rows.Next() {
		var hostname string
		if err := rows.Scan(&hostname); err != nil {
			return nil, fmt.Errorf("scan hostname: %w", err)
		}
		hostnames = append(hostnames, hostname)
	}

	return hostnames, nil
}

// Exists checks if a server with the given hostname exists
func (r *WAFServersRepository) Exists(ctx context.Context, hostname string) (bool, error) {
	query := `
		SELECT count() > 0
		FROM waf_monitored_servers FINAL
		WHERE hostname = ? AND enabled = 1
	`

	var exists bool
	if err := r.conn.DB().QueryRow(ctx, query, hostname).Scan(&exists); err != nil {
		return false, fmt.Errorf("check exists: %w", err)
	}

	return exists, nil
}
