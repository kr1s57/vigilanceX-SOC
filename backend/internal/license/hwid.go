package license

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// HardwareID represents a unique identifier for the machine
type HardwareID struct {
	ProductUUID string `json:"product_uuid"` // From /sys/class/dmi/id/product_uuid
	MachineID   string `json:"machine_id"`   // From /etc/machine-id
	ContainerID string `json:"container_id"` // Docker container ID if applicable
	Hash        string `json:"hash"`         // SHA256 of combined IDs
}

// GenerateHardwareID creates a unique, stable HardwareID for the current machine
// Optimized for VM environments (Hyper-V, VMware, KVM) and Docker containers
// Priority: machine-id (host) > product_uuid (VM) > container_id (fallback only)
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
	// DO NOT include container ID if we have machine-id (it changes on container recreation)
	if hwid.MachineID == "" && hwid.ProductUUID == "" {
		if containerID := getDockerContainerID(); containerID != "" {
			hwid.ContainerID = normalizeID(containerID)
		}
	}

	// Ensure we have at least one ID
	if hwid.ProductUUID == "" && hwid.MachineID == "" && hwid.ContainerID == "" {
		return nil, fmt.Errorf("unable to generate hardware ID: no identifiers found")
	}

	// Generate hash from stable IDs only (exclude container ID if we have better options)
	hwid.Hash = hwid.generateStableHash()

	return hwid, nil
}

// String returns the hash representation of the HardwareID
func (h *HardwareID) String() string {
	return h.Hash
}

// IsValid checks if the HardwareID has been properly generated
func (h *HardwareID) IsValid() bool {
	return h.Hash != "" && (h.ProductUUID != "" || h.MachineID != "" || h.ContainerID != "")
}

// generateHash creates a SHA256 hash from all available identifiers (legacy)
func (h *HardwareID) generateHash() string {
	// Combine all available IDs in a deterministic order
	combined := fmt.Sprintf("VX:%s:%s:%s",
		h.ProductUUID,
		h.MachineID,
		h.ContainerID,
	)

	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// generateStableHash creates a SHA256 hash using only stable identifiers
// This ensures the hash doesn't change when Docker containers are recreated
func (h *HardwareID) generateStableHash() string {
	// Use only stable IDs (machine-id and product_uuid)
	// Container ID is excluded to ensure stability across container restarts
	combined := fmt.Sprintf("VX2:%s:%s",
		h.MachineID,
		h.ProductUUID,
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
	// Remove hyphens and convert to lowercase for consistency
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
								return containerID[:12] // Return short ID
							}
						}
					}
				}
			}
		}
	}

	// Check for .dockerenv file (indicates Docker environment)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		// Try hostname as container ID
		if hostname, err := os.Hostname(); err == nil && len(hostname) == 12 {
			return hostname
		}
	}

	return ""
}

// GetHardwareIDString is a convenience function that returns just the hash string
func GetHardwareIDString() (string, error) {
	hwid, err := GenerateHardwareID()
	if err != nil {
		return "", err
	}
	return hwid.String(), nil
}
