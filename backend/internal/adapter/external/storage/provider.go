package storage

import (
	"context"
	"io"
	"time"
)

// Provider defines the interface for external storage backends
type Provider interface {
	// Connect establishes connection to the storage backend
	Connect(ctx context.Context) error

	// Disconnect closes the connection
	Disconnect() error

	// IsConnected returns true if currently connected
	IsConnected() bool

	// Write writes data to a file at the given path
	Write(ctx context.Context, path string, data []byte) error

	// WriteStream writes from a reader to a file
	WriteStream(ctx context.Context, path string, reader io.Reader) error

	// Read reads a file and returns its contents
	Read(ctx context.Context, path string) ([]byte, error)

	// Delete removes a file
	Delete(ctx context.Context, path string) error

	// List lists files in a directory
	List(ctx context.Context, path string) ([]FileInfo, error)

	// Exists checks if a file exists
	Exists(ctx context.Context, path string) (bool, error)

	// MkdirAll creates a directory and all parent directories
	MkdirAll(ctx context.Context, path string) error

	// GetStatus returns the current status of the storage backend
	GetStatus() *Status

	// Type returns the storage type identifier
	Type() StorageType
}

// StorageType identifies the type of storage backend
type StorageType string

const (
	StorageTypeSMB   StorageType = "smb"
	StorageTypeS3    StorageType = "s3"
	StorageTypeLocal StorageType = "local"
)

// FileInfo contains metadata about a file
type FileInfo struct {
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	IsDir        bool      `json:"is_dir"`
	ModifiedTime time.Time `json:"modified_time"`
}

// Status contains the current status of a storage backend
type Status struct {
	Type         StorageType `json:"type"`
	Connected    bool        `json:"connected"`
	Host         string      `json:"host,omitempty"`
	Share        string      `json:"share,omitempty"`
	LastError    string      `json:"last_error,omitempty"`
	LastSuccess  time.Time   `json:"last_success,omitempty"`
	BytesWritten int64       `json:"bytes_written"`
	FilesWritten int64       `json:"files_written"`
}

// Config holds configuration for storage backends
type Config struct {
	// Common
	Enabled bool        `json:"enabled"`
	Type    StorageType `json:"type"`

	// SMB specific
	SMB *SMBConfig `json:"smb,omitempty"`

	// S3 specific (future)
	S3 *S3Config `json:"s3,omitempty"`

	// Archive settings
	Archive *ArchiveConfig `json:"archive,omitempty"`
}

// SMBConfig holds SMB-specific configuration
type SMBConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Share    string `json:"share"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
	BasePath string `json:"base_path"` // Subdirectory within share

	// Security options (v3.51)
	RequireSigning bool   `json:"require_signing"` // Enforce message signing
	MinVersion     string `json:"min_version"`     // Minimum SMB version: "3.0", "3.0.2", "3.1.1"
}

// S3Config holds S3/MinIO configuration (future implementation)
type S3Config struct {
	Endpoint        string `json:"endpoint"`
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	UseSSL          bool   `json:"use_ssl"`
	BasePath        string `json:"base_path"`
}

// ArchiveConfig holds settings for log archiving
type ArchiveConfig struct {
	Enabled         bool   `json:"enabled"`
	Compression     bool   `json:"compression"`      // gzip compression
	RotationPattern string `json:"rotation_pattern"` // daily, hourly
	RetentionDays   int    `json:"retention_days"`
	MaxFileSize     int64  `json:"max_file_size"` // bytes, for rotation
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		Type:    StorageTypeSMB,
		SMB: &SMBConfig{
			Port:           445,
			Domain:         "WORKGROUP",
			BasePath:       "vigilancex",
			RequireSigning: true,  // Security: enforce message signing
			MinVersion:     "3.0", // Security: minimum SMB 3.0 (encrypted)
		},
		Archive: &ArchiveConfig{
			Enabled:         true,
			Compression:     true,
			RotationPattern: "daily",
			RetentionDays:   90,
			MaxFileSize:     100 * 1024 * 1024, // 100MB
		},
	}
}
