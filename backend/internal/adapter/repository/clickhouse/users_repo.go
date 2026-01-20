package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// UsersRepository handles user data persistence in ClickHouse
type UsersRepository struct {
	conn *Connection
}

// NewUsersRepository creates a new users repository
func NewUsersRepository(conn *Connection) *UsersRepository {
	return &UsersRepository{conn: conn}
}

// GetByUsername retrieves a user by username
func (r *UsersRepository) GetByUsername(ctx context.Context, username string) (*entity.User, error) {
	query := `
		SELECT
			toString(id) as id,
			username,
			email,
			password_hash,
			role,
			is_active,
			last_login,
			created_at,
			updated_at
		FROM users FINAL
		WHERE username = ? AND is_active = 1
		LIMIT 1
	`

	row := r.conn.DB().QueryRow(ctx, query, username)

	var user entity.User
	var isActive uint8
	var lastLogin *time.Time

	if err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&isActive,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	user.IsActive = isActive == 1
	user.LastLogin = lastLogin

	return &user, nil
}

// GetByID retrieves a user by ID
func (r *UsersRepository) GetByID(ctx context.Context, id string) (*entity.User, error) {
	query := `
		SELECT
			toString(id) as id,
			username,
			email,
			password_hash,
			role,
			is_active,
			last_login,
			created_at,
			updated_at
		FROM users FINAL
		WHERE id = ?
		LIMIT 1
	`

	row := r.conn.DB().QueryRow(ctx, query, id)

	var user entity.User
	var isActive uint8
	var lastLogin *time.Time

	if err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&isActive,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	user.IsActive = isActive == 1
	user.LastLogin = lastLogin

	return &user, nil
}

// List retrieves all active users
// v3.57.117: Filter out inactive (deleted) users
func (r *UsersRepository) List(ctx context.Context) ([]entity.User, error) {
	query := `
		SELECT
			toString(id) as id,
			username,
			email,
			password_hash,
			role,
			is_active,
			last_login,
			created_at,
			updated_at
		FROM users FINAL
		WHERE is_active = 1
		ORDER BY username
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	var users []entity.User
	for rows.Next() {
		var user entity.User
		var isActive uint8
		var lastLogin *time.Time

		if err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.PasswordHash,
			&user.Role,
			&isActive,
			&lastLogin,
			&user.CreatedAt,
			&user.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan user row: %w", err)
		}

		user.IsActive = isActive == 1
		user.LastLogin = lastLogin
		users = append(users, user)
	}

	return users, nil
}

// Create creates a new user
func (r *UsersRepository) Create(ctx context.Context, user *entity.User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	now := time.Now()
	isActive := uint8(0)
	if user.IsActive {
		isActive = 1
	}

	query := `
		INSERT INTO users (
			id, username, email, password_hash, role,
			is_active, last_login, created_at, updated_at, version
		) VALUES (
			?, ?, ?, ?, ?,
			?, ?, ?, ?, toUnixTimestamp(now())
		)
	`

	if err := r.conn.DB().Exec(ctx, query,
		user.ID,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.Role,
		isActive,
		user.LastLogin,
		now,
		now,
	); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	user.CreatedAt = now
	user.UpdatedAt = now

	return nil
}

// Update updates an existing user
func (r *UsersRepository) Update(ctx context.Context, user *entity.User) error {
	isActive := uint8(0)
	if user.IsActive {
		isActive = 1
	}

	query := `
		INSERT INTO users (
			id, username, email, password_hash, role,
			is_active, last_login, created_at, updated_at, version
		) VALUES (
			?, ?, ?, ?, ?,
			?, ?, ?, now(), toUnixTimestamp(now())
		)
	`

	if err := r.conn.DB().Exec(ctx, query,
		user.ID,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.Role,
		isActive,
		user.LastLogin,
		user.CreatedAt,
	); err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	user.UpdatedAt = time.Now()
	return nil
}

// Delete soft-deletes a user by marking as inactive
func (r *UsersRepository) Delete(ctx context.Context, id string) error {
	// Get existing user first
	user, err := r.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Mark as inactive
	user.IsActive = false
	return r.Update(ctx, user)
}

// UpdateLastLogin updates the last login timestamp
func (r *UsersRepository) UpdateLastLogin(ctx context.Context, id string) error {
	user, err := r.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	now := time.Now()
	user.LastLogin = &now
	return r.Update(ctx, user)
}

// UpdatePassword updates a user's password hash
func (r *UsersRepository) UpdatePassword(ctx context.Context, id string, passwordHash string) error {
	user, err := r.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.PasswordHash = passwordHash
	return r.Update(ctx, user)
}

// Count returns the total number of users
func (r *UsersRepository) Count(ctx context.Context) (int, error) {
	query := `SELECT count() FROM users FINAL WHERE is_active = 1`

	var count uint64
	if err := r.conn.DB().QueryRow(ctx, query).Scan(&count); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}

	return int(count), nil
}

// ExistsByUsername checks if a username already exists
func (r *UsersRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	query := `SELECT count() FROM users FINAL WHERE username = ?`

	var count uint64
	if err := r.conn.DB().QueryRow(ctx, query, username).Scan(&count); err != nil {
		return false, fmt.Errorf("check username exists: %w", err)
	}

	return count > 0, nil
}
