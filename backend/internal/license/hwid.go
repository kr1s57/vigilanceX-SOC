package license

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// DBQuerier is an interface for executing queries (compatible with ClickHouse driver)
type DBQuerier interface {
	QueryRow(ctx context.Context, query string, args ...interface{}) RowScanner
}

// RowScanner is an interface for scanning query results
type RowScanner interface {
	Scan(dest ...interface{}) error
}

// ClickHouseRowQuerier is the interface that ClickHouse connections implement
type ClickHouseRowQuerier interface {
	QueryRow(ctx context.Context, query string, args ...interface{}) RowScanner
}

// ClickHouseAdapter wraps a ClickHouse connection to implement DBQuerier
type ClickHouseAdapter struct {
	queryFunc func(ctx context.Context, query string, args ...interface{}) RowScanner
}

// NewClickHouseAdapter creates a new adapter for ClickHouse connections
// Pass a function that wraps the connection's QueryRow method
func NewClickHouseAdapter(queryRowFunc func(ctx context.Context, query string, args ...interface{}) RowScanner) *ClickHouseAdapter {
	return &ClickHouseAdapter{queryFunc: queryRowFunc}
}

// QueryRow implements DBQuerier interface
func (a *ClickHouseAdapter) QueryRow(ctx context.Context, query string, args ...interface{}) RowScanner {
	return a.queryFunc(ctx, query, args...)
}

// HardwareID represents a unique identifier for the machine
// v3.0: Now includes firewall serial for stronger binding
type HardwareID struct {
	ProductUUID    string `json:"product_uuid"`    // From /sys/class/dmi/id/product_uuid
	MachineID      string `json:"machine_id"`      // From /etc/machine-id
	ContainerID    string `json:"container_id"`    // Docker container ID if applicable
	FirewallSerial string `json:"firewall_serial"` // v3.0: From syslog device_serial_id
	FirewallModel  string `json:"firewall_model"`  // v3.0: From syslog device_model
	FirewallName   string `json:"firewall_name"`   // v3.0: From syslog device_name
	Hash           string `json:"hash"`            // SHA256 of combined IDs
}

// FirewallInfo holds firewall identification data extracted from syslog
type FirewallInfo struct {
	Serial    string `json:"serial"`
	Model     string `json:"model"`
	Name      string `json:"name"`
	FirstSeen time.Time `json:"first_seen"`
}

// GenerateHardwareID creates a unique, stable HardwareID for the current machine
// This version does NOT include firewall serial - use GenerateHardwareIDWithFirewall for full binding
func GenerateHardwareID() (*HardwareID, error) {
	hwid := &HardwareID{}

	// Try to get machine ID (systemd) - BEST for Docker with mounted /etc/machine-id
	if machineID, err := readFileContent("/etc/machine-id"); err == nil && machineID != "" {
		hwid.MachineID = normalizeID(machineID)
	}

	// Try to get product UUID (best for VMs without Docker)
	if uuid, err := readFileContent("/sys/class/dmi/id/product_uuid"); err == nil && uuid != "" {
		hwid.ProductUUID = normalizeID(uuid)
	}

	// Container ID is only used as FALLBACK if no stable ID is available
	if hwid.MachineID == "" && hwid.ProductUUID == "" {
		if containerID := getDockerContainerID(); containerID != "" {
			hwid.ContainerID = normalizeID(containerID)
		}
	}

	// Ensure we have at least one ID
	if hwid.ProductUUID == "" && hwid.MachineID == "" && hwid.ContainerID == "" {
		return nil, fmt.Errorf("unable to generate hardware ID: no identifiers found")
	}

	// Generate hash (legacy VX2 format without firewall)
	hwid.Hash = hwid.generateLegacyHash()

	return hwid, nil
}

// GenerateHardwareIDWithFirewall creates a HardwareID with firewall binding
// This is the v3.0 secure version that binds to both VM and firewall
func GenerateHardwareIDWithFirewall(ctx context.Context, db DBQuerier, database string) (*HardwareID, error) {
	hwid, err := GenerateHardwareID()
	if err != nil {
		return nil, err
	}

	if db == nil {
		slog.Warn("No database connection provided, using legacy binding")
		return hwid, nil
	}

	// Try to get firewall info from ClickHouse
	fwInfo, err := GetFirewallInfoFromClickHouse(ctx, db, database)
	if err != nil {
		slog.Warn("Could not get firewall info from ClickHouse", "error", err)
		// Continue with legacy hash if no firewall info available
		return hwid, nil
	}

	if fwInfo != nil && fwInfo.Serial != "" {
		hwid.FirewallSerial = fwInfo.Serial
		hwid.FirewallModel = fwInfo.Model
		hwid.FirewallName = fwInfo.Name
		// Regenerate hash with firewall binding (VX3 format)
		hwid.Hash = hwid.generateSecureHash()
		slog.Info("Hardware ID generated with firewall binding",
			"firewall_serial", fwInfo.Serial,
			"firewall_model", fwInfo.Model,
			"hash_prefix", hwid.Hash[:16]+"...")
	}

	return hwid, nil
}

// GetFirewallInfoFromClickHouse extracts firewall identification from syslog data
func GetFirewallInfoFromClickHouse(ctx context.Context, db DBQuerier, database string) (*FirewallInfo, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	// Query to extract firewall info from raw logs
	// The device_serial_id is present in all Sophos XGS syslog messages
	query := fmt.Sprintf(`
		SELECT
			extractAll(raw_log, 'device_serial_id="([^"]+)"')[1] as serial,
			extractAll(raw_log, 'device_model="([^"]+)"')[1] as model,
			extractAll(raw_log, 'device_name="([^"]+)"')[1] as name,
			min(timestamp) as first_seen
		FROM %s.events
		WHERE raw_log LIKE '%%device_serial_id%%'
		GROUP BY serial, model, name
		HAVING serial != ''
		ORDER BY first_seen ASC
		LIMIT 1
	`, database)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	row := db.QueryRow(ctx, query)

	var info FirewallInfo
	err := row.Scan(&info.Serial, &info.Model, &info.Name, &info.FirstSeen)
	if err != nil {
		return nil, fmt.Errorf("failed to query firewall info: %w", err)
	}

	if info.Serial == "" {
		return nil, fmt.Errorf("firewall serial is empty")
	}

	return &info, nil
}

// SetFirewallInfo updates the hardware ID with firewall information
// Used when loading from persisted store
func (h *HardwareID) SetFirewallInfo(serial, model, name string) {
	h.FirewallSerial = serial
	h.FirewallModel = model
	h.FirewallName = name
	if serial != "" {
		h.Hash = h.generateSecureHash()
	}
}

// HasFirewallBinding returns true if the hardware ID includes firewall binding
func (h *HardwareID) HasFirewallBinding() bool {
	return h.FirewallSerial != ""
}

// String returns the hash representation of the HardwareID
func (h *HardwareID) String() string {
	return h.Hash
}

// IsValid checks if the HardwareID has been properly generated
func (h *HardwareID) IsValid() bool {
	return h.Hash != "" && (h.ProductUUID != "" || h.MachineID != "" || h.ContainerID != "")
}

// IsSecure checks if the HardwareID has full firewall binding (v3.0)
func (h *HardwareID) IsSecure() bool {
	return h.IsValid() && h.FirewallSerial != ""
}

// generateLegacyHash creates a SHA256 hash using only VM identifiers (VX2 format)
// This is used as fallback when firewall info is not available
func (h *HardwareID) generateLegacyHash() string {
	combined := fmt.Sprintf("VX2:%s:%s",
		h.MachineID,
		h.ProductUUID,
	)

	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// generateSecureHash creates a SHA256 hash with firewall binding (VX3 format)
// This is the v3.0 secure version that includes the firewall serial
func (h *HardwareID) generateSecureHash() string {
	// VX3 format: includes firewall serial for dual binding
	// Format: VX3:machine_id:firewall_serial
	combined := fmt.Sprintf("VX3:%s:%s",
		h.MachineID,
		h.FirewallSerial,
	)

	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// readFileContent reads and returns the content of a file, trimmed
func readFileContent(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// normalizeID cleans up an ID string (removes hyphens, lowercase)
func normalizeID(id string) string {
	cleaned := strings.ReplaceAll(id, "-", "")
	return strings.ToLower(strings.TrimSpace(cleaned))
}

// getDockerContainerID attempts to get the Docker container ID
func getDockerContainerID() string {
	// Check cgroup v2 (modern Docker)
	if content, err := readFileContent("/proc/self/mountinfo"); err == nil {
		if strings.Contains(content, "docker") {
			// Try to extract container ID from cgroup
			if cgroupContent, err := readFileContent("/proc/1/cgroup"); err == nil {
				lines := strings.Split(cgroupContent, "\n")
				for _, line := range lines {
					if strings.Contains(line, "docker") {
						parts := strings.Split(line, "/")
						if len(parts) > 0 {
							containerID := parts[len(parts)-1]
							if len(containerID) >= 12 {
								return containerID[:12]
							}
						}
					}
				}
			}
		}
	}

	// Check for .dockerenv file
	if _, err := os.Stat("/.dockerenv"); err == nil {
		if hostname, err := os.Hostname(); err == nil && len(hostname) == 12 {
			return hostname
		}
	}

	return ""
}

// GetHardwareIDString is a convenience function that returns just the hash string
// Note: This returns legacy VX2 hash without firewall binding
func GetHardwareIDString() (string, error) {
	hwid, err := GenerateHardwareID()
	if err != nil {
		return "", err
	}
	return hwid.String(), nil
}

// GetHardwareIDWithFirewallString returns the secure VX3 hash with firewall binding
func GetHardwareIDWithFirewallString(ctx context.Context, db DBQuerier, database string) (string, error) {
	hwid, err := GenerateHardwareIDWithFirewall(ctx, db, database)
	if err != nil {
		return "", err
	}
	return hwid.String(), nil
}
