// v3.57.107: Admin Console handler for terminal commands
package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// ConsoleHandler handles admin console commands
type ConsoleHandler struct {
	composeFile string
	workDir     string
}

// NewConsoleHandler creates a new console handler
func NewConsoleHandler(composeFile, workDir string) *ConsoleHandler {
	return &ConsoleHandler{
		composeFile: composeFile,
		workDir:     workDir,
	}
}

// CommandRequest represents a console command request
type CommandRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

// CommandResponse represents a console command response
type CommandResponse struct {
	Success bool     `json:"success"`
	Output  string   `json:"output"`
	Error   string   `json:"error,omitempty"`
	Lines   []string `json:"lines,omitempty"`
}

// Available services for docker operations
var allowedServices = map[string]string{
	"api":        "vigilance-api",
	"frontend":   "vigilance-frontend",
	"clickhouse": "vigilance-clickhouse",
	"redis":      "vigilance-redis",
	"vector":     "vigilance-vector",
}

// ExecuteCommand handles POST /api/admin/console/execute
func (h *ConsoleHandler) ExecuteCommand(w http.ResponseWriter, r *http.Request) {
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	cmd := strings.ToLower(strings.TrimSpace(req.Command))
	args := req.Args

	var resp CommandResponse

	switch cmd {
	case "help":
		resp = h.cmdHelp()
	case "status":
		resp = h.cmdStatus()
	case "version":
		resp = h.cmdVersion()
	case "health":
		resp = h.cmdHealth()
	case "db-stats":
		resp = h.cmdDBStats()
	case "cache-clear":
		resp = h.cmdCacheClear()
	case "cache-stats":
		resp = h.cmdCacheStats()
	case "restart":
		resp = h.cmdRestart(args)
	case "stop":
		resp = h.cmdStop(args)
	case "start":
		resp = h.cmdStart(args)
	case "restart-all":
		resp = h.cmdRestartAll()
	case "logs":
		resp = h.cmdLogs(args)
	default:
		resp = CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Unknown command: %s. Type 'help' for available commands.", cmd),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetLogs handles GET /api/admin/console/logs
func (h *ConsoleHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	lines := r.URL.Query().Get("lines")
	since := r.URL.Query().Get("since")

	if service == "" {
		service = "api"
	}

	containerName, ok := allowedServices[service]
	if !ok {
		ErrorResponse(w, http.StatusBadRequest, "Invalid service name", nil)
		return
	}

	if lines == "" {
		lines = "100"
	}

	args := []string{"logs", "--tail", lines}
	if since != "" {
		args = append(args, "--since", since)
	}
	args = append(args, containerName)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()

	resp := CommandResponse{
		Success: err == nil,
		Output:  string(output),
	}

	if err != nil {
		resp.Error = err.Error()
	}

	// Split into lines for easier frontend display
	resp.Lines = strings.Split(strings.TrimSpace(string(output)), "\n")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// StreamLogs handles Server-Sent Events for live log streaming
func (h *ConsoleHandler) StreamLogs(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	if service == "" {
		service = "api"
	}

	containerName, ok := allowedServices[service]
	if !ok {
		ErrorResponse(w, http.StatusBadRequest, "Invalid service name", nil)
		return
	}

	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "logs", "-f", "--tail", "50", containerName)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(w, "data: {\"error\": \"Failed to create pipe: %v\"}\n\n", err)
		return
	}

	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(w, "data: {\"error\": \"Failed to start command: %v\"}\n\n", err)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		fmt.Fprintf(w, "data: {\"error\": \"Streaming not supported\"}\n\n")
		return
	}

	// Stream stdout
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			escaped := escapeJSON(line)
			fmt.Fprintf(w, "data: {\"line\": \"%s\", \"stream\": \"stdout\"}\n\n", escaped)
			flusher.Flush()
		}
	}()

	// Stream stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			escaped := escapeJSON(line)
			fmt.Fprintf(w, "data: {\"line\": \"%s\", \"stream\": \"stderr\"}\n\n", escaped)
			flusher.Flush()
		}
	}()

	// Wait for context cancellation or command completion
	<-ctx.Done()
	cmd.Process.Kill()
	cmd.Wait()
}

// GetServices returns the list of available services
func (h *ConsoleHandler) GetServices(w http.ResponseWriter, r *http.Request) {
	services := make([]map[string]string, 0)
	for name, container := range allowedServices {
		services = append(services, map[string]string{
			"name":      name,
			"container": container,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

// Command implementations

func (h *ConsoleHandler) cmdHelp() CommandResponse {
	help := `VIGILANCE X Admin Console
=========================

Available Commands:
  status        - Show stack services status
  version       - Show version information
  health        - Health check all services
  db-stats      - Show ClickHouse database statistics
  cache-stats   - Show Redis cache statistics
  cache-clear   - Clear Redis cache
  restart <svc> - Restart a service (api, frontend, clickhouse, redis, vector)
  stop <svc>    - Stop a service (except api)
  start <svc>   - Start a service
  restart-all   - Restart entire stack
  logs <svc>    - View service logs (last 100 lines)
  help          - Show this help message

Examples:
  > status
  > restart frontend
  > logs api
  > cache-clear`

	return CommandResponse{
		Success: true,
		Output:  help,
		Lines:   strings.Split(help, "\n"),
	}
}

func (h *ConsoleHandler) cmdStatus() CommandResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}", "--filter", "name=vigilance")
	output, err := cmd.CombinedOutput()

	return CommandResponse{
		Success: err == nil,
		Output:  string(output),
		Lines:   strings.Split(strings.TrimSpace(string(output)), "\n"),
		Error:   errToString(err),
	}
}

func (h *ConsoleHandler) cmdVersion() CommandResponse {
	version := `VIGILANCE X v3.57.107

Stack Components:
  API:        Go 1.22 (Chi router, Clean Architecture)
  Frontend:   React 18 + TypeScript + Tailwind + Shadcn
  Database:   ClickHouse 24.1
  Cache:      Redis 7
  Ingestion:  Vector.dev (Syslog)
  Deploy:     Docker Compose

Build Info:
  Architecture: amd64
  Platform:     linux`

	return CommandResponse{
		Success: true,
		Output:  version,
		Lines:   strings.Split(version, "\n"),
	}
}

func (h *ConsoleHandler) cmdHealth() CommandResponse {
	var results []string
	allHealthy := true

	// Check Docker services
	for name, container := range allowedServices {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Status}}", container)
		output, err := cmd.Output()
		status := strings.TrimSpace(string(output))
		if err != nil || status != "running" {
			results = append(results, fmt.Sprintf("  %s: UNHEALTHY (%s)", name, status))
			allHealthy = false
		} else {
			results = append(results, fmt.Sprintf("  %s: HEALTHY", name))
		}
		cancel()
	}

	header := "Service Health Check"
	if allHealthy {
		header += " - All services running"
	} else {
		header += " - Some services unhealthy"
	}

	output := header + "\n" + strings.Repeat("-", 40) + "\n" + strings.Join(results, "\n")
	return CommandResponse{
		Success: allHealthy,
		Output:  output,
		Lines:   append([]string{header, strings.Repeat("-", 40)}, results...),
	}
}

func (h *ConsoleHandler) cmdDBStats() CommandResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get ClickHouse stats via docker exec
	query := `SELECT
		database,
		table,
		formatReadableSize(sum(bytes_on_disk)) as size,
		formatReadableQuantity(sum(rows)) as rows,
		count() as parts
	FROM system.parts
	WHERE database = 'vigilance_x' AND active
	GROUP BY database, table
	ORDER BY sum(bytes_on_disk) DESC`

	cmd := exec.CommandContext(ctx, "docker", "exec", "vigilance-clickhouse",
		"clickhouse-client", "--query", query, "--format", "PrettyCompact")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return CommandResponse{
			Success: false,
			Output:  "Failed to get database stats",
			Error:   errToString(err) + "\n" + string(output),
		}
	}

	result := "ClickHouse Database Statistics\n" + strings.Repeat("-", 40) + "\n" + string(output)
	return CommandResponse{
		Success: true,
		Output:  result,
		Lines:   strings.Split(result, "\n"),
	}
}

func (h *ConsoleHandler) cmdCacheStats() CommandResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", "vigilance-redis", "redis-cli", "info", "memory")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return CommandResponse{
			Success: false,
			Output:  "Failed to get cache stats",
			Error:   errToString(err),
		}
	}

	result := "Redis Cache Statistics\n" + strings.Repeat("-", 40) + "\n" + string(output)
	return CommandResponse{
		Success: true,
		Output:  result,
		Lines:   strings.Split(result, "\n"),
	}
}

func (h *ConsoleHandler) cmdCacheClear() CommandResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", "vigilance-redis", "redis-cli", "FLUSHALL")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return CommandResponse{
			Success: false,
			Output:  "Failed to clear cache",
			Error:   errToString(err),
		}
	}

	return CommandResponse{
		Success: true,
		Output:  "Cache cleared successfully\n" + strings.TrimSpace(string(output)),
	}
}

func (h *ConsoleHandler) cmdRestart(args []string) CommandResponse {
	if len(args) == 0 {
		return CommandResponse{
			Success: false,
			Error:   "Usage: restart <service>\nServices: api, frontend, clickhouse, redis, vector",
		}
	}

	service := strings.ToLower(args[0])
	containerName, ok := allowedServices[service]
	if !ok {
		return CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Unknown service: %s\nAvailable: api, frontend, clickhouse, redis, vector", service),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "restart", containerName)
	output, err := cmd.CombinedOutput()

	return CommandResponse{
		Success: err == nil,
		Output:  fmt.Sprintf("Restarting %s...\n%s", containerName, string(output)),
		Error:   errToString(err),
	}
}

func (h *ConsoleHandler) cmdStop(args []string) CommandResponse {
	if len(args) == 0 {
		return CommandResponse{
			Success: false,
			Error:   "Usage: stop <service>\nServices: api, frontend, clickhouse, redis, vector",
		}
	}

	service := strings.ToLower(args[0])
	containerName, ok := allowedServices[service]
	if !ok {
		return CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Unknown service: %s", service),
		}
	}

	// Don't allow stopping the API from the API
	if service == "api" {
		return CommandResponse{
			Success: false,
			Error:   "Cannot stop the API service from within the API. Use restart instead.",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "stop", containerName)
	output, err := cmd.CombinedOutput()

	return CommandResponse{
		Success: err == nil,
		Output:  fmt.Sprintf("Stopping %s...\n%s", containerName, string(output)),
		Error:   errToString(err),
	}
}

func (h *ConsoleHandler) cmdStart(args []string) CommandResponse {
	if len(args) == 0 {
		return CommandResponse{
			Success: false,
			Error:   "Usage: start <service>\nServices: api, frontend, clickhouse, redis, vector",
		}
	}

	service := strings.ToLower(args[0])
	containerName, ok := allowedServices[service]
	if !ok {
		return CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Unknown service: %s", service),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "start", containerName)
	output, err := cmd.CombinedOutput()

	return CommandResponse{
		Success: err == nil,
		Output:  fmt.Sprintf("Starting %s...\n%s", containerName, string(output)),
		Error:   errToString(err),
	}
}

func (h *ConsoleHandler) cmdRestartAll() CommandResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Use docker compose to restart all services
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", h.composeFile, "restart")
	cmd.Dir = h.workDir
	output, err := cmd.CombinedOutput()

	return CommandResponse{
		Success: err == nil,
		Output:  fmt.Sprintf("Restarting all services...\n%s", string(output)),
		Error:   errToString(err),
	}
}

func (h *ConsoleHandler) cmdLogs(args []string) CommandResponse {
	service := "api"
	if len(args) > 0 {
		service = strings.ToLower(args[0])
	}

	containerName, ok := allowedServices[service]
	if !ok {
		return CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Unknown service: %s\nAvailable: api, frontend, clickhouse, redis, vector", service),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "logs", "--tail", "100", containerName)
	output, err := cmd.CombinedOutput()

	return CommandResponse{
		Success: err == nil,
		Output:  string(output),
		Lines:   strings.Split(strings.TrimSpace(string(output)), "\n"),
		Error:   errToString(err),
	}
}

func errToString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}
