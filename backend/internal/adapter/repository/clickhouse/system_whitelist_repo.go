package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// SystemWhitelistRepository handles system whitelist CRUD operations
type SystemWhitelistRepository struct {
	conn *Connection
}

// NewSystemWhitelistRepository creates a new system whitelist repository
func NewSystemWhitelistRepository(conn *Connection) *SystemWhitelistRepository {
	return &SystemWhitelistRepository{conn: conn}
}

// CustomEntry represents a custom system whitelist entry in the database
type CustomEntry struct {
	ID          string    `ch:"id"`
	IP          string    `ch:"ip"`
	Name        string    `ch:"name"`
	Provider    string    `ch:"provider"`
	Category    string    `ch:"category"`
	Description string    `ch:"description"`
	IsActive    uint8     `ch:"is_active"`
	CreatedAt   time.Time `ch:"created_at"`
	UpdatedAt   time.Time `ch:"updated_at"`
	CreatedBy   string    `ch:"created_by"`
}

// List retrieves all custom system whitelist entries
func (r *SystemWhitelistRepository) List(ctx context.Context) ([]entity.CustomSystemWhitelistEntry, error) {
	query := `
		SELECT
			toString(id) as id,
			ip,
			name,
			provider,
			category,
			description,
			is_active,
			created_at,
			updated_at,
			created_by
		FROM system_whitelist FINAL
		WHERE is_active = 1
		ORDER BY category, name
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query system whitelist: %w", err)
	}
	defer rows.Close()

	var entries []entity.CustomSystemWhitelistEntry
	for rows.Next() {
		var e CustomEntry
		if err := rows.Scan(
			&e.ID,
			&e.IP,
			&e.Name,
			&e.Provider,
			&e.Category,
			&e.Description,
			&e.IsActive,
			&e.CreatedAt,
			&e.UpdatedAt,
			&e.CreatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		entries = append(entries, entity.CustomSystemWhitelistEntry{
			ID:          e.ID,
			IP:          e.IP,
			Name:        e.Name,
			Provider:    e.Provider,
			Category:    e.Category,
			Description: e.Description,
			CreatedAt:   e.CreatedAt,
			UpdatedAt:   e.UpdatedAt,
			CreatedBy:   e.CreatedBy,
		})
	}

	return entries, nil
}

// GetByIP retrieves a custom entry by IP
func (r *SystemWhitelistRepository) GetByIP(ctx context.Context, ip string) (*entity.CustomSystemWhitelistEntry, error) {
	query := `
		SELECT
			toString(id) as id,
			ip,
			name,
			provider,
			category,
			description,
			is_active,
			created_at,
			updated_at,
			created_by
		FROM system_whitelist FINAL
		WHERE ip = ? AND is_active = 1
		LIMIT 1
	`

	var e CustomEntry
	row := r.conn.DB().QueryRow(ctx, query, ip)
	if err := row.Scan(
		&e.ID,
		&e.IP,
		&e.Name,
		&e.Provider,
		&e.Category,
		&e.Description,
		&e.IsActive,
		&e.CreatedAt,
		&e.UpdatedAt,
		&e.CreatedBy,
	); err != nil {
		return nil, fmt.Errorf("get by IP: %w", err)
	}

	return &entity.CustomSystemWhitelistEntry{
		ID:          e.ID,
		IP:          e.IP,
		Name:        e.Name,
		Provider:    e.Provider,
		Category:    e.Category,
		Description: e.Description,
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
		CreatedBy:   e.CreatedBy,
	}, nil
}

// Create adds a new custom system whitelist entry
func (r *SystemWhitelistRepository) Create(ctx context.Context, entry *entity.CustomSystemWhitelistEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}

	now := time.Now()
	entry.CreatedAt = now
	entry.UpdatedAt = now

	query := `
		INSERT INTO system_whitelist (id, ip, name, provider, category, description, is_active, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
	`

	if err := r.conn.DB().Exec(ctx, query,
		entry.ID,
		entry.IP,
		entry.Name,
		entry.Provider,
		entry.Category,
		entry.Description,
		entry.CreatedAt,
		entry.UpdatedAt,
		entry.CreatedBy,
	); err != nil {
		return fmt.Errorf("insert system whitelist entry: %w", err)
	}

	return nil
}

// Update modifies an existing custom system whitelist entry
func (r *SystemWhitelistRepository) Update(ctx context.Context, entry *entity.CustomSystemWhitelistEntry) error {
	entry.UpdatedAt = time.Now()

	query := `
		INSERT INTO system_whitelist (id, ip, name, provider, category, description, is_active, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
	`

	if err := r.conn.DB().Exec(ctx, query,
		entry.ID,
		entry.IP,
		entry.Name,
		entry.Provider,
		entry.Category,
		entry.Description,
		entry.CreatedAt,
		entry.UpdatedAt,
		entry.CreatedBy,
	); err != nil {
		return fmt.Errorf("update system whitelist entry: %w", err)
	}

	return nil
}

// Delete removes a custom system whitelist entry (soft delete)
func (r *SystemWhitelistRepository) Delete(ctx context.Context, id string) error {
	// First get the existing entry
	query := `
		SELECT
			toString(id) as id,
			ip,
			name,
			provider,
			category,
			description,
			created_at,
			created_by
		FROM system_whitelist FINAL
		WHERE toString(id) = ? AND is_active = 1
		LIMIT 1
	`

	var e CustomEntry
	row := r.conn.DB().QueryRow(ctx, query, id)
	if err := row.Scan(
		&e.ID,
		&e.IP,
		&e.Name,
		&e.Provider,
		&e.Category,
		&e.Description,
		&e.CreatedAt,
		&e.CreatedBy,
	); err != nil {
		return fmt.Errorf("entry not found: %w", err)
	}

	// Insert with is_active = 0 to soft delete
	insertQuery := `
		INSERT INTO system_whitelist (id, ip, name, provider, category, description, is_active, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
	`

	if err := r.conn.DB().Exec(ctx, insertQuery,
		e.ID,
		e.IP,
		e.Name,
		e.Provider,
		e.Category,
		e.Description,
		e.CreatedAt,
		time.Now(),
		e.CreatedBy,
	); err != nil {
		return fmt.Errorf("delete system whitelist entry: %w", err)
	}

	return nil
}
