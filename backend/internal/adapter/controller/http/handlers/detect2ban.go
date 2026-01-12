package handlers

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/usecase/detect2ban"
)

// Detect2BanHandler handles Detect2Ban engine HTTP requests
type Detect2BanHandler struct {
	engine     *detect2ban.Engine
	cancelFunc context.CancelFunc
	ctx        context.Context
	mu         sync.Mutex
	running    bool
	interval   time.Duration
}

// NewDetect2BanHandler creates a new Detect2Ban handler
func NewDetect2BanHandler(engine *detect2ban.Engine) *Detect2BanHandler {
	return &Detect2BanHandler{
		engine:   engine,
		interval: 30 * time.Second, // Default check interval
	}
}

// SetAutoStarted marks the engine as auto-started (called from main.go)
// This syncs the handler state with the externally started engine
func (h *Detect2BanHandler) SetAutoStarted(ctx context.Context, cancel context.CancelFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ctx = ctx
	h.cancelFunc = cancel
	h.running = true
}

// Detect2BanStatus represents the engine status response
type Detect2BanStatus struct {
	Enabled         bool     `json:"enabled"`
	Running         bool     `json:"running"`
	ScenarioCount   int      `json:"scenario_count"`
	LoadedScenarios []string `json:"loaded_scenarios"`
	CheckInterval   string   `json:"check_interval"`
}

// GetStatus returns the Detect2Ban engine status
// GET /api/v1/detect2ban/status
func (h *Detect2BanHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	running := h.running
	h.mu.Unlock()

	var status *detect2ban.EngineStatus
	if h.engine != nil {
		status = h.engine.GetStatus()
	}

	response := Detect2BanStatus{
		Enabled:       running,
		Running:       running,
		CheckInterval: h.interval.String(),
	}

	if status != nil {
		response.ScenarioCount = status.ScenarioCount
		response.LoadedScenarios = status.LoadedScenarios
	}

	JSONResponse(w, http.StatusOK, response)
}

// Enable starts the Detect2Ban engine
// POST /api/v1/detect2ban/enable
func (h *Detect2BanHandler) Enable(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		ErrorResponse(w, http.StatusServiceUnavailable, "Detect2Ban engine not configured", nil)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Detect2Ban already running",
			"status":  "running",
		})
		return
	}

	// Create cancellable context
	h.ctx, h.cancelFunc = context.WithCancel(context.Background())
	h.running = true

	// Start engine in goroutine
	go h.engine.Start(h.ctx, h.interval)

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Detect2Ban engine started",
		"status":  "running",
	})
}

// Disable stops the Detect2Ban engine
// POST /api/v1/detect2ban/disable
func (h *Detect2BanHandler) Disable(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Detect2Ban already stopped",
			"status":  "stopped",
		})
		return
	}

	// Cancel context to stop engine
	if h.cancelFunc != nil {
		h.cancelFunc()
	}
	h.running = false

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Detect2Ban engine stopped",
		"status":  "stopped",
	})
}

// Toggle switches the Detect2Ban engine state
// POST /api/v1/detect2ban/toggle
func (h *Detect2BanHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	isRunning := h.running
	h.mu.Unlock()

	if isRunning {
		h.Disable(w, r)
	} else {
		h.Enable(w, r)
	}
}

// GetScenarios returns loaded scenarios
// GET /api/v1/detect2ban/scenarios
func (h *Detect2BanHandler) GetScenarios(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"scenarios": []interface{}{},
		})
		return
	}

	scenarios := h.engine.GetScenarios()
	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"scenarios": scenarios,
	})
}
