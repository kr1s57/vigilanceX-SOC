package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Manager handles storage providers and log archiving
type Manager struct {
	config     *Config
	provider   Provider
	configPath string
	mu         sync.RWMutex

	// Buffer for batch writes
	buffer     []LogEntry
	bufferMu   sync.Mutex
	bufferSize int

	// Archive settings
	currentFile    string
	currentDay     string
	bytesInCurrent int64
}

// LogEntry represents a log entry to be archived
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	LogType   string    `json:"log_type"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	Action    string    `json:"action"`
	RawLog    string    `json:"raw_log"`
}

// NewManager creates a new storage manager
func NewManager(configPath string) *Manager {
	return &Manager{
		configPath: configPath,
		config:     DefaultConfig(),
		bufferSize: 1000, // Flush every 1000 entries
		buffer:     make([]LogEntry, 0, 1000),
	}
}

// LoadConfig loads configuration from disk
func (m *Manager) LoadConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default config
			return m.saveConfigLocked()
		}
		return fmt.Errorf("failed to read config: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	m.config = &config
	return nil
}

// SaveConfig saves configuration to disk
func (m *Manager) SaveConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveConfigLocked()
}

func (m *Manager) saveConfigLocked() error {
	// Ensure directory exists
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(m.configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// GetConfig returns a copy of the current configuration
func (m *Manager) GetConfig() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent modification
	configCopy := *m.config
	if m.config.SMB != nil {
		smbCopy := *m.config.SMB
		// Mask password
		smbCopy.Password = "********"
		configCopy.SMB = &smbCopy
	}
	if m.config.Archive != nil {
		archiveCopy := *m.config.Archive
		configCopy.Archive = &archiveCopy
	}
	return &configCopy
}

// UpdateConfig updates the configuration
func (m *Manager) UpdateConfig(config *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Preserve password if masked
	if config.SMB != nil && config.SMB.Password == "********" && m.config.SMB != nil {
		config.SMB.Password = m.config.SMB.Password
	}

	m.config = config
	return m.saveConfigLocked()
}

// UpdateSMBConfig updates only the SMB configuration
func (m *Manager) UpdateSMBConfig(smb *SMBConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Preserve password if masked
	if smb.Password == "********" && m.config.SMB != nil {
		smb.Password = m.config.SMB.Password
	}

	m.config.SMB = smb
	return m.saveConfigLocked()
}

// Connect establishes connection to the configured storage backend
func (m *Manager) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.config.Enabled {
		return fmt.Errorf("storage is disabled")
	}

	switch m.config.Type {
	case StorageTypeSMB:
		if m.config.SMB == nil {
			return fmt.Errorf("SMB configuration is missing")
		}
		m.provider = NewSMBProvider(m.config.SMB)
		return m.provider.Connect(ctx)

	case StorageTypeS3:
		return fmt.Errorf("S3 storage not implemented yet")

	default:
		return fmt.Errorf("unknown storage type: %s", m.config.Type)
	}
}

// Disconnect closes the storage connection
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.provider != nil {
		return m.provider.Disconnect()
	}
	return nil
}

// IsConnected returns true if storage is connected
func (m *Manager) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.provider == nil {
		return false
	}
	return m.provider.IsConnected()
}

// GetStatus returns the current storage status
func (m *Manager) GetStatus() *Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.provider == nil {
		return &Status{
			Type:      m.config.Type,
			Connected: false,
		}
	}
	return m.provider.GetStatus()
}

// TestConnection tests the storage connection
func (m *Manager) TestConnection(ctx context.Context, config *SMBConfig) error {
	// Create temporary provider
	provider := NewSMBProvider(config)

	if err := provider.Connect(ctx); err != nil {
		return err
	}
	defer provider.Disconnect()

	// Run test
	return provider.TestConnection(ctx)
}

// ArchiveLog adds a log entry to the buffer for archiving
func (m *Manager) ArchiveLog(entry LogEntry) error {
	m.mu.RLock()
	enabled := m.config.Enabled && m.config.Archive != nil && m.config.Archive.Enabled
	m.mu.RUnlock()

	if !enabled {
		return nil
	}

	m.bufferMu.Lock()
	m.buffer = append(m.buffer, entry)
	shouldFlush := len(m.buffer) >= m.bufferSize
	m.bufferMu.Unlock()

	if shouldFlush {
		return m.Flush(context.Background())
	}
	return nil
}

// Flush writes buffered logs to storage
func (m *Manager) Flush(ctx context.Context) error {
	m.bufferMu.Lock()
	if len(m.buffer) == 0 {
		m.bufferMu.Unlock()
		return nil
	}
	entries := m.buffer
	m.buffer = make([]LogEntry, 0, m.bufferSize)
	m.bufferMu.Unlock()

	m.mu.RLock()
	provider := m.provider
	config := m.config
	m.mu.RUnlock()

	if provider == nil || !provider.IsConnected() {
		// Re-add entries to buffer for retry
		m.bufferMu.Lock()
		m.buffer = append(entries, m.buffer...)
		m.bufferMu.Unlock()
		return fmt.Errorf("storage not connected")
	}

	// Determine file path based on rotation pattern
	now := time.Now()
	var filename string

	switch config.Archive.RotationPattern {
	case "hourly":
		filename = fmt.Sprintf("logs/%s/vigilancex_%s.jsonl",
			now.Format("2006-01-02"),
			now.Format("2006-01-02_15"))
	default: // daily
		filename = fmt.Sprintf("logs/%s/vigilancex_%s.jsonl",
			now.Format("2006-01-02"),
			now.Format("2006-01-02"))
	}

	// Serialize entries
	var data []byte
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		data = append(data, line...)
		data = append(data, '\n')
	}

	// Check if we should compress
	if config.Archive.Compression {
		if smbProvider, ok := provider.(*SMBProvider); ok {
			return smbProvider.WriteCompressed(ctx, filename, data)
		}
	}

	// Append to existing file or create new
	existing, _ := provider.Read(ctx, filename)
	data = append(existing, data...)

	return provider.Write(ctx, filename, data)
}

// StartArchiver starts the background archiving service
func (m *Manager) StartArchiver(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Flush every 30 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// Final flush before exit
				m.Flush(context.Background())
				return
			case <-ticker.C:
				if m.IsConnected() {
					if err := m.Flush(ctx); err != nil {
						slog.Warn("[STORAGE] Flush failed", "error", err)
					}
				}
			}
		}
	}()

	slog.Info("[STORAGE] Archiver started")
}

// Enable enables storage and connects
func (m *Manager) Enable(ctx context.Context) error {
	m.mu.Lock()
	m.config.Enabled = true
	m.saveConfigLocked()
	m.mu.Unlock()

	return m.Connect(ctx)
}

// Disable disables storage and disconnects
func (m *Manager) Disable() error {
	// Flush remaining buffer
	m.Flush(context.Background())

	m.mu.Lock()
	m.config.Enabled = false
	m.saveConfigLocked()
	m.mu.Unlock()

	return m.Disconnect()
}
