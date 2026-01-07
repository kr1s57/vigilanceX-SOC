package detect2ban

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/entity"
	"github.com/kr1s57/vigilancex/internal/usecase/bans"
	"github.com/kr1s57/vigilancex/internal/usecase/threats"
)

// Engine is the Detect2Ban detection engine
type Engine struct {
	scenarios      []*Scenario
	eventsRepo     *clickhouse.EventsRepository
	bansService    *bans.Service
	threatsService *threats.Service
	mu             sync.RWMutex
	running        bool
	stopCh         chan struct{}
}

// Scenario represents a detection scenario loaded from YAML
type Scenario struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Enabled     bool         `yaml:"enabled"`
	Conditions  []Condition  `yaml:"conditions"`
	Aggregation *Aggregation `yaml:"aggregation"`
	Action      Action       `yaml:"action"`
	Cooldown    string       `yaml:"cooldown"` // e.g., "5m", "1h"
}

// Condition defines a trigger condition
type Condition struct {
	Field    string      `yaml:"field"`    // log_type, severity, action, category, etc.
	Operator string      `yaml:"operator"` // eq, ne, in, contains, gt, lt
	Value    interface{} `yaml:"value"`
}

// Aggregation defines counting rules
type Aggregation struct {
	GroupBy   string `yaml:"group_by"`  // src_ip, dst_ip, hostname
	Window    string `yaml:"window"`    // e.g., "5m", "1h"
	Threshold int    `yaml:"threshold"` // minimum count to trigger
	Distinct  string `yaml:"distinct"`  // optional: count distinct values
}

// Action defines what happens when scenario triggers
type Action struct {
	Type            string `yaml:"type"`             // ban, alert, log
	Duration        string `yaml:"duration"`         // for bans: "1h", "4h", "permanent"
	ValidateThreat  bool   `yaml:"validate_threat"`  // check threat intel first
	ThreatThreshold int    `yaml:"threat_threshold"` // minimum threat score to ban
	Reason          string `yaml:"reason"`           // ban reason template
}

// Config holds engine configuration
type Config struct {
	ScenariosDir      string
	CheckInterval     time.Duration
	EnableThreatCheck bool
}

// NewEngine creates a new Detect2Ban engine
func NewEngine(cfg Config, eventsRepo *clickhouse.EventsRepository, bansService *bans.Service, threatsService *threats.Service) *Engine {
	return &Engine{
		eventsRepo:     eventsRepo,
		bansService:    bansService,
		threatsService: threatsService,
		stopCh:         make(chan struct{}),
	}
}

// LoadScenarios loads all YAML scenarios from directory
func (e *Engine) LoadScenarios(dir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.scenarios = nil

	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("glob scenarios: %w", err)
	}

	for _, file := range files {
		scenario, err := e.loadScenario(file)
		if err != nil {
			log.Printf("[DETECT2BAN] Failed to load %s: %v", file, err)
			continue
		}

		if scenario.Enabled {
			e.scenarios = append(e.scenarios, scenario)
			log.Printf("[DETECT2BAN] Loaded scenario: %s", scenario.Name)
		}
	}

	log.Printf("[DETECT2BAN] Loaded %d scenarios", len(e.scenarios))
	return nil
}

// loadScenario loads a single scenario from YAML file
func (e *Engine) loadScenario(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var scenario Scenario
	if err := yaml.Unmarshal(data, &scenario); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	return &scenario, nil
}

// Start begins the detection loop
func (e *Engine) Start(ctx context.Context, interval time.Duration) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.mu.Unlock()

	log.Printf("[DETECT2BAN] Engine started, check interval: %v", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.Stop()
			return
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.runDetectionCycle(ctx)
		}
	}
}

// Stop stops the detection engine
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		close(e.stopCh)
		e.running = false
		log.Printf("[DETECT2BAN] Engine stopped")
	}
}

// runDetectionCycle runs all scenarios
func (e *Engine) runDetectionCycle(ctx context.Context) {
	e.mu.RLock()
	scenarios := e.scenarios
	e.mu.RUnlock()

	for _, scenario := range scenarios {
		matches, err := e.evaluateScenario(ctx, scenario)
		if err != nil {
			log.Printf("[DETECT2BAN] Scenario %s error: %v", scenario.Name, err)
			continue
		}

		for _, match := range matches {
			e.handleMatch(ctx, scenario, match)
		}
	}
}

// ScenarioMatch represents an IP that matched a scenario
type ScenarioMatch struct {
	IP         string
	EventCount int64
	FirstEvent time.Time
	LastEvent  time.Time
}

// evaluateScenario evaluates a scenario and returns matching IPs
func (e *Engine) evaluateScenario(ctx context.Context, scenario *Scenario) ([]ScenarioMatch, error) {
	if scenario.Aggregation == nil {
		return nil, nil
	}

	// Parse window duration
	window, err := time.ParseDuration(scenario.Aggregation.Window)
	if err != nil {
		window = 5 * time.Minute
	}

	// Build query based on conditions
	query := e.buildQuery(scenario, window)

	rows, err := e.eventsRepo.RawQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("execute query: %w", err)
	}
	defer rows.Close()

	var matches []ScenarioMatch
	for rows.Next() {
		var match ScenarioMatch
		if err := rows.Scan(&match.IP, &match.EventCount, &match.FirstEvent, &match.LastEvent); err != nil {
			continue
		}

		if match.EventCount >= int64(scenario.Aggregation.Threshold) {
			matches = append(matches, match)
		}
	}

	return matches, nil
}

// buildQuery constructs a ClickHouse query from scenario conditions
func (e *Engine) buildQuery(scenario *Scenario, window time.Duration) string {
	// Build WHERE clause from conditions
	whereClause := fmt.Sprintf("timestamp >= now() - INTERVAL %d SECOND", int(window.Seconds()))

	for _, cond := range scenario.Conditions {
		clause := e.conditionToSQL(cond)
		if clause != "" {
			whereClause += " AND " + clause
		}
	}

	groupBy := scenario.Aggregation.GroupBy
	if groupBy == "" {
		groupBy = "src_ip"
	}

	query := fmt.Sprintf(`
		SELECT
			%s as ip,
			count() as event_count,
			min(timestamp) as first_event,
			max(timestamp) as last_event
		FROM events
		WHERE %s
		GROUP BY %s
		HAVING event_count >= %d
		ORDER BY event_count DESC
		LIMIT 100
	`, groupBy, whereClause, groupBy, scenario.Aggregation.Threshold)

	return query
}

// conditionToSQL converts a condition to SQL
func (e *Engine) conditionToSQL(cond Condition) string {
	value := cond.Value

	switch cond.Operator {
	case "eq", "=", "==":
		return fmt.Sprintf("%s = '%v'", cond.Field, value)
	case "ne", "!=", "<>":
		return fmt.Sprintf("%s != '%v'", cond.Field, value)
	case "in":
		if arr, ok := value.([]interface{}); ok {
			values := ""
			for i, v := range arr {
				if i > 0 {
					values += ", "
				}
				values += fmt.Sprintf("'%v'", v)
			}
			return fmt.Sprintf("%s IN (%s)", cond.Field, values)
		}
	case "contains", "like":
		return fmt.Sprintf("%s LIKE '%%%v%%'", cond.Field, value)
	case "gt", ">":
		return fmt.Sprintf("%s > %v", cond.Field, value)
	case "lt", "<":
		return fmt.Sprintf("%s < %v", cond.Field, value)
	case "gte", ">=":
		return fmt.Sprintf("%s >= %v", cond.Field, value)
	case "lte", "<=":
		return fmt.Sprintf("%s <= %v", cond.Field, value)
	}

	return ""
}

// handleMatch processes a scenario match
func (e *Engine) handleMatch(ctx context.Context, scenario *Scenario, match ScenarioMatch) {
	log.Printf("[DETECT2BAN] Scenario '%s' triggered for IP %s (count: %d)",
		scenario.Name, match.IP, match.EventCount)

	// Check if already banned
	existingBan, err := e.bansService.GetBan(ctx, match.IP)
	if err == nil && existingBan != nil {
		if existingBan.Status == entity.BanStatusActive || existingBan.Status == entity.BanStatusPermanent {
			log.Printf("[DETECT2BAN] IP %s already banned, skipping", match.IP)
			return
		}
	}

	// Validate with threat intelligence if configured
	if scenario.Action.ValidateThreat && e.threatsService != nil {
		threatResult, err := e.threatsService.CheckIP(ctx, match.IP)
		if err != nil {
			log.Printf("[DETECT2BAN] Threat check failed for %s: %v", match.IP, err)
		} else if threatResult.AggregatedScore < scenario.Action.ThreatThreshold {
			log.Printf("[DETECT2BAN] IP %s threat score %d below threshold %d, skipping ban",
				match.IP, threatResult.AggregatedScore, scenario.Action.ThreatThreshold)
			return
		}
	}

	// Execute action
	switch scenario.Action.Type {
	case "ban":
		e.executeBan(ctx, scenario, match)
	case "alert":
		e.executeAlert(scenario, match)
	case "log":
		log.Printf("[DETECT2BAN] LOG: %s - IP %s, count %d",
			scenario.Name, match.IP, match.EventCount)
	}
}

// executeBan bans an IP based on scenario action
func (e *Engine) executeBan(ctx context.Context, scenario *Scenario, match ScenarioMatch) {
	reason := scenario.Action.Reason
	if reason == "" {
		reason = fmt.Sprintf("Auto-ban: %s (%d events)", scenario.Name, match.EventCount)
	}

	// Parse duration
	var durationDays *int
	permanent := false

	if scenario.Action.Duration == "permanent" {
		permanent = true
	} else if d, err := time.ParseDuration(scenario.Action.Duration); err == nil {
		days := int(d.Hours() / 24)
		if days < 1 {
			days = 1
		}
		durationDays = &days
	}

	req := &entity.BanRequest{
		IP:           match.IP,
		Reason:       reason,
		DurationDays: durationDays,
		Permanent:    permanent,
		TriggerRule:  scenario.Name,
		PerformedBy:  "detect2ban",
	}

	ban, err := e.bansService.BanIP(ctx, req)
	if err != nil {
		log.Printf("[DETECT2BAN] Failed to ban %s: %v", match.IP, err)
		return
	}

	log.Printf("[DETECT2BAN] Banned IP %s (status: %s, expires: %v)",
		match.IP, ban.Status, ban.ExpiresAt)
}

// executeAlert sends an alert (placeholder for webhooks)
func (e *Engine) executeAlert(scenario *Scenario, match ScenarioMatch) {
	log.Printf("[DETECT2BAN] ALERT: %s triggered for IP %s (%d events)",
		scenario.Name, match.IP, match.EventCount)
	// TODO: Implement webhook notifications
}

// GetScenarios returns loaded scenarios
func (e *Engine) GetScenarios() []*Scenario {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Scenario, len(e.scenarios))
	copy(result, e.scenarios)
	return result
}

// GetStatus returns engine status
func (e *Engine) GetStatus() *EngineStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return &EngineStatus{
		Running:         e.running,
		ScenarioCount:   len(e.scenarios),
		LoadedScenarios: e.getScenarioNames(),
	}
}

// EngineStatus represents the engine status
type EngineStatus struct {
	Running         bool     `json:"running"`
	ScenarioCount   int      `json:"scenario_count"`
	LoadedScenarios []string `json:"loaded_scenarios"`
}

func (e *Engine) getScenarioNames() []string {
	names := make([]string, len(e.scenarios))
	for i, s := range e.scenarios {
		names[i] = s.Name
	}
	return names
}
