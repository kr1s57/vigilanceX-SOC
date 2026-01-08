package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LicenseStore handles local persistence of license information
type LicenseStore struct {
	path      string
	encKey    []byte
	mu        sync.RWMutex
	hardwareID string
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
}

// NewLicenseStore creates a new license store
func NewLicenseStore(path string) (*LicenseStore, error) {
	// Get hardware ID for encryption key derivation
	hwid, err := GetHardwareIDString()
	if err != nil {
		return nil, fmt.Errorf("failed to get hardware ID: %w", err)
	}

	// Derive encryption key from hardware ID (prevents license file copying)
	key := deriveKey(hwid)

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

// Save persists the license information to disk
func (s *LicenseStore) Save(license *StoredLicense) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Set hardware ID
	license.HardwareID = s.hardwareID
	license.LastValidated = time.Now()

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
	if license.HardwareID != s.hardwareID {
		return nil, fmt.Errorf("license hardware ID mismatch")
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
	salt := "vigilancex-license-key-v1"
	hash := sha256.Sum256([]byte(hwid + salt))
	return hash[:]
}

// GetHardwareID returns the hardware ID used by this store
func (s *LicenseStore) GetHardwareID() string {
	return s.hardwareID
}
