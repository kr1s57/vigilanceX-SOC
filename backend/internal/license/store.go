package license

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LicenseStore handles local persistence of license information
type LicenseStore struct {
	path       string
	encKey     []byte
	mu         sync.RWMutex
	hardwareID *HardwareID
}

// StoredLicense represents the persisted license data
type StoredLicense struct {
	LicenseKey    string    `json:"license_key"`
	CustomerName  string    `json:"customer_name"`
	ExpiresAt     time.Time `json:"expires_at"`
	MaxFirewalls  int       `json:"max_firewalls"`
	Features      []string  `json:"features"`
	IsValid       bool      `json:"is_valid"`
	Status        string    `json:"status"`
	HardwareID    string    `json:"hardware_id"`
	LastValidated time.Time `json:"last_validated"`
	GraceStart    time.Time `json:"grace_start,omitempty"`
	// v3.0: Firewall binding info
	FirewallSerial string `json:"firewall_serial,omitempty"`
	FirewallModel  string `json:"firewall_model,omitempty"`
	FirewallName   string `json:"firewall_name,omitempty"`
	BindingVersion string `json:"binding_version,omitempty"` // "VX2" or "VX3"
}

// NewLicenseStore creates a new license store (legacy - without firewall binding)
func NewLicenseStore(path string) (*LicenseStore, error) {
	// Get hardware ID for encryption key derivation
	hwid, err := GenerateHardwareID()
	if err != nil {
		return nil, fmt.Errorf("failed to get hardware ID: %w", err)
	}

	// Derive encryption key from hardware ID (prevents license file copying)
	key := deriveKey(hwid.Hash)

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	return &LicenseStore{
		path:       path,
		encKey:     key,
		hardwareID: hwid,
	}, nil
}

// NewLicenseStoreWithFirewall creates a license store with firewall binding (v3.0)
func NewLicenseStoreWithFirewall(ctx context.Context, path string, db DBQuerier, database string) (*LicenseStore, error) {
	// Get hardware ID with firewall binding
	hwid, err := GenerateHardwareIDWithFirewall(ctx, db, database)
	if err != nil {
		return nil, fmt.Errorf("failed to get hardware ID: %w", err)
	}

	// Derive encryption key from hardware ID
	key := deriveKey(hwid.Hash)

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	store := &LicenseStore{
		path:       path,
		encKey:     key,
		hardwareID: hwid,
	}

	// Try to load existing license and check if we need to migrate
	if store.Exists() {
		if err := store.migrateIfNeeded(ctx, db, database); err != nil {
			slog.Warn("License migration check failed", "error", err)
		}
	}

	return store, nil
}

// migrateIfNeeded checks if the license needs to be upgraded from VX2 to VX3
func (s *LicenseStore) migrateIfNeeded(ctx context.Context, db DBQuerier, database string) error {
	// Try to load with current key
	stored, err := s.Load()
	if err != nil {
		// If we can't load, it might be encrypted with old key
		// Try with legacy (VX2) key
		legacyHwid, _ := GenerateHardwareID()
		if legacyHwid != nil {
			legacyKey := deriveKey(legacyHwid.Hash)
			s.encKey = legacyKey
			stored, err = s.Load()
			if err != nil {
				return fmt.Errorf("cannot load license with either key: %w", err)
			}
			slog.Info("Loaded license with legacy VX2 key, will migrate to VX3")
		}
	}

	// Check if migration is needed
	if stored != nil && stored.BindingVersion != "VX3" && s.hardwareID.HasFirewallBinding() {
		slog.Info("Migrating license from VX2 to VX3 binding",
			"firewall_serial", s.hardwareID.FirewallSerial)

		// Update with new firewall info
		stored.FirewallSerial = s.hardwareID.FirewallSerial
		stored.FirewallModel = s.hardwareID.FirewallModel
		stored.FirewallName = s.hardwareID.FirewallName
		stored.BindingVersion = "VX3"
		stored.HardwareID = s.hardwareID.Hash

		// Update encryption key to VX3
		s.encKey = deriveKey(s.hardwareID.Hash)

		// Save with new key
		if err := s.Save(stored); err != nil {
			return fmt.Errorf("failed to save migrated license: %w", err)
		}

		slog.Info("License migrated to VX3 binding successfully")
	}

	return nil
}

// Save persists the license information to disk
func (s *LicenseStore) Save(license *StoredLicense) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Set hardware ID and firewall info
	license.HardwareID = s.hardwareID.Hash
	license.LastValidated = time.Now()

	// v3.0: Include firewall binding info
	if s.hardwareID.HasFirewallBinding() {
		license.FirewallSerial = s.hardwareID.FirewallSerial
		license.FirewallModel = s.hardwareID.FirewallModel
		license.FirewallName = s.hardwareID.FirewallName
		license.BindingVersion = "VX3"
	} else {
		license.BindingVersion = "VX2"
	}

	// Marshal to JSON
	data, err := json.Marshal(license)
	if err != nil {
		return fmt.Errorf("failed to marshal license: %w", err)
	}

	// Encrypt the data
	encrypted, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt license: %w", err)
	}

	// Write to temp file first
	tempPath := s.path + ".tmp"
	if err := os.WriteFile(tempPath, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write license file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, s.path); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to save license file: %w", err)
	}

	return nil
}

// Load reads the license information from disk
func (s *LicenseStore) Load() (*StoredLicense, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if file exists
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return nil, fmt.Errorf("license file not found")
	}

	// Read encrypted data
	encrypted, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %w", err)
	}

	// Decrypt the data
	data, err := s.decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt license (may be from different hardware): %w", err)
	}

	// Unmarshal JSON
	var license StoredLicense
	if err := json.Unmarshal(data, &license); err != nil {
		return nil, fmt.Errorf("failed to parse license: %w", err)
	}

	// Verify hardware ID matches
	if license.HardwareID != s.hardwareID.Hash {
		return nil, fmt.Errorf("license hardware ID mismatch")
	}

	// v3.0: Verify firewall binding if present
	if license.BindingVersion == "VX3" && s.hardwareID.HasFirewallBinding() {
		if license.FirewallSerial != s.hardwareID.FirewallSerial {
			return nil, fmt.Errorf("license firewall binding mismatch (expected: %s, got: %s)",
				s.hardwareID.FirewallSerial, license.FirewallSerial)
		}
	}

	return &license, nil
}

// Delete removes the license file
func (s *LicenseStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete license file: %w", err)
	}
	return nil
}

// Exists checks if a license file exists
func (s *LicenseStore) Exists() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, err := os.Stat(s.path)
	return err == nil
}

// encrypt encrypts data using AES-GCM
func (s *LicenseStore) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts data using AES-GCM
func (s *LicenseStore) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// deriveKey derives a 32-byte AES key from the hardware ID
func deriveKey(hwid string) []byte {
	// Use SHA-256 to derive a 32-byte key
	// v3.0: Updated salt for new binding version
	salt := "vigilancex-license-key-v3"
	hash := sha256.Sum256([]byte(hwid + salt))
	return hash[:]
}

// GetHardwareID returns the hardware ID used by this store
func (s *LicenseStore) GetHardwareID() string {
	return s.hardwareID.Hash
}

// GetHardwareIDFull returns the full hardware ID struct
func (s *LicenseStore) GetHardwareIDFull() *HardwareID {
	return s.hardwareID
}

// HasSecureBinding returns true if the store uses VX3 firewall binding
func (s *LicenseStore) HasSecureBinding() bool {
	return s.hardwareID.HasFirewallBinding()
}

// GetFirewallInfo returns the firewall binding information
func (s *LicenseStore) GetFirewallInfo() *FirewallInfo {
	if !s.hardwareID.HasFirewallBinding() {
		return nil
	}
	return &FirewallInfo{
		Serial: s.hardwareID.FirewallSerial,
		Model:  s.hardwareID.FirewallModel,
		Name:   s.hardwareID.FirewallName,
	}
}
