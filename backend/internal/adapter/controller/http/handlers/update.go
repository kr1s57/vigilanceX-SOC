// v3.57.123: System Update handler for in-app updates
package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UpdateHandler handles system update operations
type UpdateHandler struct {
	composeFile string
	workDir     string

	// Update state (thread-safe)
	mu     sync.RWMutex
	status UpdateStatus
}

// VersionInfo represents version information
type VersionInfo struct {
	Installed       string `json:"installed"`
	Latest          string `json:"latest"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseURL      string `json:"release_url,omitempty"`
	ReleaseNotes    string `json:"release_notes,omitempty"`
	PublishedAt     string `json:"published_at,omitempty"`
}

// UpdateStatus represents update operation status
type UpdateStatus struct {
	Status    string `json:"status"` // idle, pulling, restarting, completed, failed
	Message   string `json:"message"`
	Progress  int    `json:"progress"` // 0-100
	StartedAt string `json:"started_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// GitHubRelease represents a GitHub release response
type GitHubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
}

// SystemStats represents system resource usage
type SystemStats struct {
	Hostname  string      `json:"hostname"`
	Platform  string      `json:"platform"`
	Uptime    string      `json:"uptime"`
	CPU       CPUStats    `json:"cpu"`
	Memory    MemoryStats `json:"memory"`
	Disk      DiskStats   `json:"disk"`
	GoRuntime GoStats     `json:"go_runtime"`
}

// CPUStats represents CPU information
type CPUStats struct {
	Cores        int     `json:"cores"`
	UsagePercent float64 `json:"usage_percent"`
	LoadAvg1     float64 `json:"load_avg_1"`
	LoadAvg5     float64 `json:"load_avg_5"`
	LoadAvg15    float64 `json:"load_avg_15"`
}

// MemoryStats represents memory information
type MemoryStats struct {
	TotalGB      float64 `json:"total_gb"`
	UsedGB       float64 `json:"used_gb"`
	FreeGB       float64 `json:"free_gb"`
	UsagePercent float64 `json:"usage_percent"`
}

// DiskStats represents disk information
type DiskStats struct {
	TotalGB      float64 `json:"total_gb"`
	UsedGB       float64 `json:"used_gb"`
	FreeGB       float64 `json:"free_gb"`
	UsagePercent float64 `json:"usage_percent"`
	MountPoint   string  `json:"mount_point"`
}

// GoStats represents Go runtime stats
type GoStats struct {
	Version     string `json:"version"`
	Goroutines  int    `json:"goroutines"`
	HeapAllocMB uint64 `json:"heap_alloc_mb"`
}

// Constants
const (
	GitHubAPIURL     = "https://api.github.com/repos/kr1s57/vigilanceX-SOC/releases/latest"
	InstalledVersion = "3.58.104" // Fallback if env not set
	StatusIdle       = "idle"
	StatusPulling    = "pulling"
	StatusRestarting = "restarting"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
)

// compareVersions compares two semantic versions (X.YY.Z format)
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		if i < len(parts1) {
			p1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			p2, _ = strconv.Atoi(parts2[i])
		}
		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}
	return 0
}

// NewUpdateHandler creates a new update handler
func NewUpdateHandler(composeFile, workDir string) *UpdateHandler {
	return &UpdateHandler{
		composeFile: composeFile,
		workDir:     workDir,
		status: UpdateStatus{
			Status:  StatusIdle,
			Message: "System ready",
		},
	}
}

// GetVersion returns current and latest version info
// GET /api/v1/system/version
func (h *UpdateHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	// Get installed version from env or fallback
	installed := os.Getenv("VGX_VERSION")
	if installed == "" {
		installed = InstalledVersion
	}
	// Remove 'v' prefix if present
	installed = strings.TrimPrefix(installed, "v")

	// Fetch latest version from GitHub
	latest, releaseInfo := h.fetchLatestVersion()

	// v3.57.124: Use semver comparison - update only if installed < latest
	versionInfo := VersionInfo{
		Installed:       installed,
		Latest:          latest,
		UpdateAvailable: latest != "" && compareVersions(installed, latest) < 0,
	}

	if releaseInfo != nil {
		versionInfo.ReleaseURL = releaseInfo.HTMLURL
		versionInfo.PublishedAt = releaseInfo.PublishedAt
		// Truncate release notes to 500 chars
		if len(releaseInfo.Body) > 500 {
			versionInfo.ReleaseNotes = releaseInfo.Body[:500] + "..."
		} else {
			versionInfo.ReleaseNotes = releaseInfo.Body
		}
	}

	JSONResponse(w, http.StatusOK, versionInfo)
}

// GetUpdateStatus returns current update status
// GET /api/v1/system/update/status
func (h *UpdateHandler) GetUpdateStatus(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	status := h.status
	h.mu.RUnlock()

	JSONResponse(w, http.StatusOK, status)
}

// TriggerUpdate initiates the update process
// POST /api/v1/system/update
func (h *UpdateHandler) TriggerUpdate(w http.ResponseWriter, r *http.Request) {
	// Check if update is already in progress
	h.mu.RLock()
	currentStatus := h.status.Status
	h.mu.RUnlock()

	if currentStatus == StatusPulling || currentStatus == StatusRestarting {
		ErrorResponse(w, http.StatusConflict, "Update already in progress", nil)
		return
	}

	// Get target version
	latest, _ := h.fetchLatestVersion()
	if latest == "" {
		ErrorResponse(w, http.StatusServiceUnavailable, "Unable to fetch latest version", nil)
		return
	}

	// Update status
	h.mu.Lock()
	h.status = UpdateStatus{
		Status:    StatusPulling,
		Message:   "Downloading new images...",
		Progress:  10,
		StartedAt: time.Now().Format(time.RFC3339),
	}
	h.mu.Unlock()

	// Return response immediately
	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Update started. Server will restart shortly.",
		"version": latest,
	})

	// Flush response
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Start update in background
	go h.performUpdate(latest)
}

// performUpdate executes the actual update process
// v3.58.102: Fixed to work on VPS - git pull + docker compose build
func (h *UpdateHandler) performUpdate(targetVersion string) {
	// Small delay to ensure response is sent
	time.Sleep(500 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	repoDir := "/opt/vigilanceX"

	// Step 1: Git fetch and reset to origin/main
	h.mu.Lock()
	h.status = UpdateStatus{
		Status:   StatusPulling,
		Message:  "Fetching latest code from repository...",
		Progress: 10,
	}
	h.mu.Unlock()

	// Git fetch
	fetchCmd := exec.CommandContext(ctx, "git", "fetch", "origin")
	fetchCmd.Dir = repoDir
	fetchOutput, fetchErr := fetchCmd.CombinedOutput()
	if fetchErr != nil {
		h.mu.Lock()
		h.status = UpdateStatus{
			Status:  StatusFailed,
			Message: "Failed to fetch from repository",
			Error:   fmt.Sprintf("%s: %s", fetchErr.Error(), string(fetchOutput)),
		}
		h.mu.Unlock()
		return
	}

	// Git reset to origin/main (handles divergent branches)
	h.mu.Lock()
	h.status = UpdateStatus{
		Status:   StatusPulling,
		Message:  "Updating to latest version...",
		Progress: 25,
	}
	h.mu.Unlock()

	resetCmd := exec.CommandContext(ctx, "git", "reset", "--hard", "origin/main")
	resetCmd.Dir = repoDir
	resetOutput, resetErr := resetCmd.CombinedOutput()
	if resetErr != nil {
		h.mu.Lock()
		h.status = UpdateStatus{
			Status:  StatusFailed,
			Message: "Failed to update code",
			Error:   fmt.Sprintf("%s: %s", resetErr.Error(), string(resetOutput)),
		}
		h.mu.Unlock()
		return
	}

	// Step 2: Docker compose build (for local builds)
	h.mu.Lock()
	h.status = UpdateStatus{
		Status:   StatusPulling,
		Message:  "Building new containers...",
		Progress: 40,
	}
	h.mu.Unlock()

	buildCmd := exec.CommandContext(ctx, "docker", "compose", "-f", h.composeFile, "build", "--no-cache")
	buildCmd.Dir = h.workDir
	buildOutput, buildErr := buildCmd.CombinedOutput()
	if buildErr != nil {
		h.mu.Lock()
		h.status = UpdateStatus{
			Status:  StatusFailed,
			Message: "Failed to build containers",
			Error:   fmt.Sprintf("%s: %s", buildErr.Error(), string(buildOutput)),
		}
		h.mu.Unlock()
		return
	}

	// Step 3: Restart containers
	h.mu.Lock()
	h.status = UpdateStatus{
		Status:   StatusRestarting,
		Message:  "Restarting services...",
		Progress: 85,
	}
	h.mu.Unlock()

	// v3.58.103: Fix update restart - detach docker compose from parent process
	// The backend container cannot restart itself directly because when Docker
	// sends SIGTERM, the child process (docker compose) is killed with it.
	// Solution: Use nohup + setsid to fully detach the restart command so it
	// survives the death of this container.
	//
	// Note: We use a shell wrapper to ensure proper detachment on Linux.
	// The log file helps debug if something goes wrong.
	restartScript := fmt.Sprintf(
		`cd %s && nohup setsid docker compose -f %s up -d --force-recreate > /tmp/vgx-update.log 2>&1 &`,
		h.workDir, h.composeFile)

	restartCmd := exec.CommandContext(ctx, "sh", "-c", restartScript)
	restartCmd.Dir = h.workDir

	if err := restartCmd.Start(); err != nil {
		h.mu.Lock()
		h.status = UpdateStatus{
			Status:  StatusFailed,
			Message: "Failed to start restart command",
			Error:   err.Error(),
		}
		h.mu.Unlock()
		return
	}

	// Don't wait for the command - it will restart us
	// The process is fully detached and will continue after we die

	// Mark status (this may not persist as we're about to be restarted)
	h.mu.Lock()
	h.status = UpdateStatus{
		Status:   StatusCompleted,
		Message:  fmt.Sprintf("Restarting to version %s...", targetVersion),
		Progress: 100,
	}
	h.mu.Unlock()

	// Give the detached process time to start before we potentially die
	time.Sleep(1 * time.Second)
}

// fetchLatestVersion fetches the latest version from GitHub
func (h *UpdateHandler) fetchLatestVersion() (string, *GitHubRelease) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", GitHubAPIURL, nil)
	if err != nil {
		return "", nil
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "VIGILANCE-X-Update-Checker")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil
	}

	var release GitHubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "", nil
	}

	// Extract version from tag (remove 'v' prefix)
	version := strings.TrimPrefix(release.TagName, "v")
	return version, &release
}

// GetSystemStats returns system resource usage
// GET /api/v1/system/stats
func (h *UpdateHandler) GetSystemStats(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	hostname, _ := os.Hostname()

	stats := SystemStats{
		Hostname: hostname,
		Platform: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Uptime:   h.getSystemUptime(),
		CPU: CPUStats{
			Cores:        runtime.NumCPU(),
			UsagePercent: h.getCPUUsage(),
			LoadAvg1:     0,
			LoadAvg5:     0,
			LoadAvg15:    0,
		},
		Memory: h.getMemoryStats(),
		Disk:   h.getDiskStats("/"),
		GoRuntime: GoStats{
			Version:     runtime.Version(),
			Goroutines:  runtime.NumGoroutine(),
			HeapAllocMB: m.Alloc / 1024 / 1024,
		},
	}

	// Get load averages
	stats.CPU.LoadAvg1, stats.CPU.LoadAvg5, stats.CPU.LoadAvg15 = h.getLoadAverages()

	JSONResponse(w, http.StatusOK, stats)
}

// getSystemUptime returns system uptime
func (h *UpdateHandler) getSystemUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "unknown"
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "unknown"
	}
	duration := time.Duration(seconds) * time.Second
	days := int(duration.Hours() / 24)
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

// getCPUUsage returns CPU usage percentage
func (h *UpdateHandler) getCPUUsage() float64 {
	// Read /proc/stat for CPU usage
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0
	}
	// First line is aggregate CPU stats
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}
	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		val, _ := strconv.ParseUint(fields[i], 10, 64)
		total += val
		if i == 4 { // idle is 4th field (0-indexed: user, nice, system, idle)
			idle = val
		}
	}
	if total == 0 {
		return 0
	}
	return float64(total-idle) / float64(total) * 100
}

// getLoadAverages returns system load averages
func (h *UpdateHandler) getLoadAverages() (float64, float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	load1, _ := strconv.ParseFloat(fields[0], 64)
	load5, _ := strconv.ParseFloat(fields[1], 64)
	load15, _ := strconv.ParseFloat(fields[2], 64)
	return load1, load5, load15
}

// getMemoryStats returns memory usage statistics
func (h *UpdateHandler) getMemoryStats() MemoryStats {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return MemoryStats{}
	}
	defer file.Close()

	var totalKB, freeKB, availableKB, buffersKB, cachedKB uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			totalKB = val
		case "MemFree:":
			freeKB = val
		case "MemAvailable:":
			availableKB = val
		case "Buffers:":
			buffersKB = val
		case "Cached:":
			cachedKB = val
		}
	}

	// If MemAvailable not present, calculate it
	if availableKB == 0 {
		availableKB = freeKB + buffersKB + cachedKB
	}

	totalGB := float64(totalKB) / 1024 / 1024
	usedKB := totalKB - availableKB
	usedGB := float64(usedKB) / 1024 / 1024
	freeGB := float64(availableKB) / 1024 / 1024
	usagePercent := float64(usedKB) / float64(totalKB) * 100

	return MemoryStats{
		TotalGB:      round2(totalGB),
		UsedGB:       round2(usedGB),
		FreeGB:       round2(freeGB),
		UsagePercent: round2(usagePercent),
	}
}

// getDiskStats returns disk usage statistics for a mount point
func (h *UpdateHandler) getDiskStats(mountPoint string) DiskStats {
	cmd := exec.Command("df", "-B1", mountPoint)
	output, err := cmd.Output()
	if err != nil {
		return DiskStats{MountPoint: mountPoint}
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return DiskStats{MountPoint: mountPoint}
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return DiskStats{MountPoint: mountPoint}
	}

	total, _ := strconv.ParseUint(fields[1], 10, 64)
	used, _ := strconv.ParseUint(fields[2], 10, 64)
	free, _ := strconv.ParseUint(fields[3], 10, 64)

	totalGB := float64(total) / 1024 / 1024 / 1024
	usedGB := float64(used) / 1024 / 1024 / 1024
	freeGB := float64(free) / 1024 / 1024 / 1024
	usagePercent := float64(used) / float64(total) * 100

	return DiskStats{
		TotalGB:      round2(totalGB),
		UsedGB:       round2(usedGB),
		FreeGB:       round2(freeGB),
		UsagePercent: round2(usagePercent),
		MountPoint:   mountPoint,
	}
}

// round2 rounds a float to 2 decimal places
func round2(val float64) float64 {
	return float64(int(val*100)) / 100
}
