package clickhouse

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/kr1s57/vigilancex/internal/config"
)

// Connection wraps the ClickHouse connection
type Connection struct {
	conn   driver.Conn
	config *config.ClickHouseConfig
	logger *slog.Logger
}

// NewConnection creates a new ClickHouse connection
func NewConnection(cfg *config.ClickHouseConfig, logger *slog.Logger) (*Connection, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.User,
			Password: cfg.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		DialTimeout:     10 * time.Second,
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		TLS: &tls.Config{
			InsecureSkipVerify: true, // For development; use proper certs in production
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to open clickhouse connection: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping clickhouse: %w", err)
	}

	logger.Info("Connected to ClickHouse",
		"host", cfg.Host,
		"port", cfg.Port,
		"database", cfg.Database,
	)

	return &Connection{
		conn:   conn,
		config: cfg,
		logger: logger,
	}, nil
}

// Conn returns the underlying connection
func (c *Connection) Conn() driver.Conn {
	return c.conn
}

// DB returns the connection for query execution (convenience method)
func (c *Connection) DB() *Connection {
	return c
}

// Close closes the connection
func (c *Connection) Close() error {
	return c.conn.Close()
}

// Ping tests the connection
func (c *Connection) Ping(ctx context.Context) error {
	return c.conn.Ping(ctx)
}

// Stats returns connection statistics
func (c *Connection) Stats() driver.Stats {
	return c.conn.Stats()
}

// Query executes a query and returns rows
func (c *Connection) Query(ctx context.Context, query string, args ...interface{}) (driver.Rows, error) {
	return c.conn.Query(ctx, query, args...)
}

// QueryRow executes a query and returns a single row
func (c *Connection) QueryRow(ctx context.Context, query string, args ...interface{}) driver.Row {
	return c.conn.QueryRow(ctx, query, args...)
}

// Exec executes a query without returning rows
func (c *Connection) Exec(ctx context.Context, query string, args ...interface{}) error {
	return c.conn.Exec(ctx, query, args...)
}

// PrepareBatch prepares a batch insert
func (c *Connection) PrepareBatch(ctx context.Context, query string) (driver.Batch, error) {
	return c.conn.PrepareBatch(ctx, query)
}
