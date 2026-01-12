package storage

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// SMB dialect constants (MS-SMB2 specification)
const (
	SMB2_DIALECT_202 uint16 = 0x0202 // SMB 2.0.2
	SMB2_DIALECT_21  uint16 = 0x0210 // SMB 2.1
	SMB3_DIALECT_30  uint16 = 0x0300 // SMB 3.0
	SMB3_DIALECT_302 uint16 = 0x0302 // SMB 3.0.2
	SMB3_DIALECT_311 uint16 = 0x0311 // SMB 3.1.1
)

// parseSMBVersion converts version string to dialect constant
func parseSMBVersion(version string) uint16 {
	switch version {
	case "2.0", "2.0.2":
		return SMB2_DIALECT_202
	case "2.1":
		return SMB2_DIALECT_21
	case "3.0":
		return SMB3_DIALECT_30
	case "3.0.2":
		return SMB3_DIALECT_302
	case "3.1.1", "3.1":
		return SMB3_DIALECT_311
	default:
		return SMB3_DIALECT_30 // Default to SMB 3.0 for security
	}
}

// SMBProvider implements the Provider interface for SMB/CIFS storage
type SMBProvider struct {
	config       *SMBConfig
	conn         net.Conn
	session      *smb2.Session
	share        *smb2.Share
	mu           sync.RWMutex
	writeMu      sync.Mutex // Mutex for WriteCompressed to prevent race conditions
	status       *Status
	bytesWritten int64
	filesWritten int64
}

// NewSMBProvider creates a new SMB storage provider
func NewSMBProvider(config *SMBConfig) *SMBProvider {
	return &SMBProvider{
		config: config,
		status: &Status{
			Type: StorageTypeSMB,
			Host: config.Host,
		},
	}
}

// Connect establishes connection to the SMB share
func (p *SMBProvider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Close any existing connection
	if p.share != nil {
		p.share.Umount()
	}
	if p.session != nil {
		p.session.Logoff()
	}
	if p.conn != nil {
		p.conn.Close()
	}

	// Determine port
	port := p.config.Port
	if port == 0 {
		port = 445
	}

	// Connect to SMB server
	addr := fmt.Sprintf("%s:%d", p.config.Host, port)
	slog.Info("[STORAGE] Connecting to SMB", "host", p.config.Host, "port", port, "share", p.config.Share)

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		p.status.LastError = fmt.Sprintf("Connection failed: %v", err)
		p.status.Connected = false
		return fmt.Errorf("failed to connect to SMB server: %w", err)
	}
	p.conn = conn

	// Create SMB session with security options (v3.51)
	d := &smb2.Dialer{
		Negotiator: smb2.Negotiator{
			RequireMessageSigning: p.config.RequireSigning,
			SpecifiedDialect:      parseSMBVersion(p.config.MinVersion),
		},
		Initiator: &smb2.NTLMInitiator{
			User:     p.config.Username,
			Password: p.config.Password,
			Domain:   p.config.Domain,
		},
	}

	// Log security settings
	slog.Info("[STORAGE] SMB security settings",
		"require_signing", p.config.RequireSigning,
		"min_version", p.config.MinVersion,
		"dialect", fmt.Sprintf("0x%04x", parseSMBVersion(p.config.MinVersion)),
	)

	session, err := d.DialContext(ctx, conn)
	if err != nil {
		p.conn.Close()
		p.status.LastError = fmt.Sprintf("SMB auth failed: %v", err)
		p.status.Connected = false
		return fmt.Errorf("failed to create SMB session: %w", err)
	}
	p.session = session

	// Mount share
	share, err := session.Mount(p.config.Share)
	if err != nil {
		p.session.Logoff()
		p.conn.Close()
		p.status.LastError = fmt.Sprintf("Mount failed: %v", err)
		p.status.Connected = false
		return fmt.Errorf("failed to mount share: %w", err)
	}
	p.share = share

	// Create base path if specified
	if p.config.BasePath != "" {
		if err := p.share.MkdirAll(p.config.BasePath, 0755); err != nil {
			slog.Warn("[STORAGE] Could not create base path", "path", p.config.BasePath, "error", err)
		}
	}

	p.status.Connected = true
	p.status.LastError = ""
	p.status.Share = p.config.Share
	p.status.LastSuccess = time.Now()

	slog.Info("[STORAGE] SMB connected successfully", "share", p.config.Share)
	return nil
}

// Disconnect closes the SMB connection
func (p *SMBProvider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.share != nil {
		p.share.Umount()
		p.share = nil
	}
	if p.session != nil {
		p.session.Logoff()
		p.session = nil
	}
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}

	p.status.Connected = false
	slog.Info("[STORAGE] SMB disconnected")
	return nil
}

// IsConnected returns true if connected to SMB
func (p *SMBProvider) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.share != nil && p.status.Connected
}

// fullPath returns the full path including base path
func (p *SMBProvider) fullPath(path string) string {
	if p.config.BasePath == "" {
		return path
	}
	return filepath.Join(p.config.BasePath, path)
}

// Write writes data to a file
func (p *SMBProvider) Write(ctx context.Context, path string, data []byte) error {
	p.mu.RLock()
	share := p.share
	p.mu.RUnlock()

	if share == nil {
		return fmt.Errorf("not connected to SMB")
	}

	fullPath := p.fullPath(path)

	// Ensure parent directory exists
	dir := filepath.Dir(fullPath)
	if err := share.MkdirAll(dir, 0755); err != nil {
		slog.Warn("[STORAGE] Could not create directory", "path", dir, "error", err)
	}

	// Create/overwrite file
	f, err := share.Create(fullPath)
	if err != nil {
		p.mu.Lock()
		p.status.LastError = fmt.Sprintf("Create failed: %v", err)
		p.mu.Unlock()
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	n, err := f.Write(data)
	if err != nil {
		p.mu.Lock()
		p.status.LastError = fmt.Sprintf("Write failed: %v", err)
		p.mu.Unlock()
		return fmt.Errorf("failed to write file: %w", err)
	}

	p.mu.Lock()
	p.bytesWritten += int64(n)
	p.filesWritten++
	p.status.BytesWritten = p.bytesWritten
	p.status.FilesWritten = p.filesWritten
	p.status.LastSuccess = time.Now()
	p.status.LastError = ""
	p.mu.Unlock()

	slog.Debug("[STORAGE] File written", "path", fullPath, "bytes", n)
	return nil
}

// WriteStream writes from a reader to a file
func (p *SMBProvider) WriteStream(ctx context.Context, path string, reader io.Reader) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read stream: %w", err)
	}
	return p.Write(ctx, path, data)
}

// WriteCompressed writes gzip-compressed data to a file, appending to existing content
// Uses mutex to prevent race conditions between concurrent writes (archiver + migration)
func (p *SMBProvider) WriteCompressed(ctx context.Context, path string, data []byte) error {
	// Lock to prevent concurrent read-modify-write race conditions
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	// Add .gz extension if not present
	if filepath.Ext(path) != ".gz" {
		path += ".gz"
	}

	// Read and decompress existing content if file exists
	var existingData []byte
	existingCompressed, err := p.Read(ctx, path)
	if err != nil {
		// File doesn't exist yet, that's OK - we'll create it
		slog.Debug("[STORAGE] No existing file (creating new)", "path", path)
	} else if len(existingCompressed) > 0 {
		gr, err := gzip.NewReader(bytes.NewReader(existingCompressed))
		if err != nil {
			slog.Warn("[STORAGE] Failed to decompress existing file, starting fresh", "path", path, "error", err)
		} else {
			existingData, err = io.ReadAll(gr)
			gr.Close()
			if err != nil {
				slog.Warn("[STORAGE] Failed to read decompressed data, starting fresh", "path", path, "error", err)
				existingData = nil
			} else {
				slog.Debug("[STORAGE] Read existing compressed data", "path", path, "existing_bytes", len(existingData))
			}
		}
	}

	// Append new data to existing
	allData := append(existingData, data...)

	// Compress combined data
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)

	if _, err := gw.Write(allData); err != nil {
		return fmt.Errorf("failed to compress: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("failed to close gzip: %w", err)
	}

	slog.Debug("[STORAGE] Writing compressed data", "path", path, "total_bytes", len(allData), "compressed_bytes", buf.Len())
	return p.Write(ctx, path, buf.Bytes())
}

// Read reads a file and returns its contents
func (p *SMBProvider) Read(ctx context.Context, path string) ([]byte, error) {
	p.mu.RLock()
	share := p.share
	p.mu.RUnlock()

	if share == nil {
		return nil, fmt.Errorf("not connected to SMB")
	}

	fullPath := p.fullPath(path)
	f, err := share.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	return io.ReadAll(f)
}

// Delete removes a file
func (p *SMBProvider) Delete(ctx context.Context, path string) error {
	p.mu.RLock()
	share := p.share
	p.mu.RUnlock()

	if share == nil {
		return fmt.Errorf("not connected to SMB")
	}

	fullPath := p.fullPath(path)
	return share.Remove(fullPath)
}

// List lists files in a directory
func (p *SMBProvider) List(ctx context.Context, path string) ([]FileInfo, error) {
	p.mu.RLock()
	share := p.share
	p.mu.RUnlock()

	if share == nil {
		return nil, fmt.Errorf("not connected to SMB")
	}

	fullPath := p.fullPath(path)
	entries, err := share.ReadDir(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %w", err)
	}

	var files []FileInfo
	for _, entry := range entries {
		files = append(files, FileInfo{
			Name:         entry.Name(),
			Path:         filepath.Join(path, entry.Name()),
			Size:         entry.Size(),
			IsDir:        entry.IsDir(),
			ModifiedTime: entry.ModTime(),
		})
	}

	return files, nil
}

// Exists checks if a file exists
func (p *SMBProvider) Exists(ctx context.Context, path string) (bool, error) {
	p.mu.RLock()
	share := p.share
	p.mu.RUnlock()

	if share == nil {
		return false, fmt.Errorf("not connected to SMB")
	}

	fullPath := p.fullPath(path)
	_, err := share.Stat(fullPath)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// MkdirAll creates a directory and all parent directories
func (p *SMBProvider) MkdirAll(ctx context.Context, path string) error {
	p.mu.RLock()
	share := p.share
	p.mu.RUnlock()

	if share == nil {
		return fmt.Errorf("not connected to SMB")
	}

	fullPath := p.fullPath(path)
	return share.MkdirAll(fullPath, 0755)
}

// GetStatus returns the current status with real filesystem stats
func (p *SMBProvider) GetStatus() *Status {
	p.mu.RLock()
	defer p.mu.RUnlock()

	status := &Status{
		Type:        StorageTypeSMB,
		Connected:   p.status.Connected,
		Host:        p.status.Host,
		Share:       p.status.Share,
		LastError:   p.status.LastError,
		LastSuccess: p.status.LastSuccess,
	}

	// Calculate real stats from filesystem if connected
	if p.share != nil && p.status.Connected {
		files, bytes := p.calculateStatsLocked()
		status.FilesWritten = files
		status.BytesWritten = bytes
	}

	return status
}

// calculateStatsLocked scans the filesystem to get real file counts and sizes
// Must be called with mu held
func (p *SMBProvider) calculateStatsLocked() (int64, int64) {
	var totalFiles int64
	var totalBytes int64

	// Start from base path (e.g., "vigilancex/logs")
	basePath := p.config.BasePath
	if basePath == "" {
		basePath = "."
	}

	// Recursive scan with depth limit to avoid infinite loops
	p.scanDirectory(basePath, &totalFiles, &totalBytes, 0, 5)

	return totalFiles, totalBytes
}

// scanDirectory recursively scans a directory and accumulates file stats
func (p *SMBProvider) scanDirectory(path string, totalFiles *int64, totalBytes *int64, depth, maxDepth int) {
	if depth > maxDepth || p.share == nil {
		return
	}

	entries, err := p.share.ReadDir(path)
	if err != nil {
		// Directory doesn't exist or not accessible - that's ok
		return
	}

	for _, entry := range entries {
		fullPath := filepath.Join(path, entry.Name())
		if entry.IsDir() {
			// Recurse into subdirectory
			p.scanDirectory(fullPath, totalFiles, totalBytes, depth+1, maxDepth)
		} else {
			// Count file
			*totalFiles++
			*totalBytes += entry.Size()
		}
	}
}

// Type returns the storage type
func (p *SMBProvider) Type() StorageType {
	return StorageTypeSMB
}

// TestConnection tests the SMB connection with a write/read/delete cycle
func (p *SMBProvider) TestConnection(ctx context.Context) error {
	testFile := fmt.Sprintf(".vigilancex_test_%d.tmp", time.Now().UnixNano())
	testData := []byte("VIGILANCE X Storage Test")

	// Write
	if err := p.Write(ctx, testFile, testData); err != nil {
		return fmt.Errorf("write test failed: %w", err)
	}

	// Read
	data, err := p.Read(ctx, testFile)
	if err != nil {
		return fmt.Errorf("read test failed: %w", err)
	}

	if string(data) != string(testData) {
		return fmt.Errorf("data mismatch")
	}

	// Delete
	if err := p.Delete(ctx, testFile); err != nil {
		return fmt.Errorf("delete test failed: %w", err)
	}

	slog.Info("[STORAGE] SMB connection test passed")
	return nil
}
