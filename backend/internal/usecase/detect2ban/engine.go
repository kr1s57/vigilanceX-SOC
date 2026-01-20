package detect2ban

import (
	"context"
	"fmt"
	"log"
	"net"
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

// ProtectedNetworks defines IP ranges that should NEVER be banned
// These are local/internal networks and critical infrastructure IPs
var ProtectedNetworks = []string{
	"10.0.0.0/8",     // Private Class A
	"192.168.0.0/16", // Private Class C
	"172.16.0.0/12",  // Private Class B (172.16.x.x - 172.31.x.x)
	"127.0.0.0/8",    // Loopback
	"169.254.0.0/16", // Link-local
	"0.0.0.0/32",     // Invalid
}

// ProtectedIPs defines specific IPs that should NEVER be banned
// Critical infrastructure IPs (XGS interfaces, gateways, etc.)
var ProtectedIPs = []string{
	"192.168.1.13", // Sophos XGS WAN interface
	"192.168.1.1",  // Sophos XGS gateway/router
	"0.0.0.0",
	"127.0.0.1",
}

// parsedProtectedNetworks holds parsed CIDR networks (initialized once)
var parsedProtectedNetworks []*net.IPNet

func init() {
	for _, cidr := range ProtectedNetworks {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedProtectedNetworks = append(parsedProtectedNetworks, network)
		}
	}
}

// IsProtectedIP checks if an IP should never be banned
// Returns true for local/internal IPs and critical infrastructure
func IsProtectedIP(ipStr string) bool {
	// Check specific protected IPs first
	for _, protectedIP := range ProtectedIPs {
		if ipStr == protectedIP {
			return true
		}
	}

	// Parse the IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Invalid IP, let it through (will fail later)
	}

	// Check against protected networks
	for _, network := range parsedProtectedNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// GetProtectionReason returns why an IP is protected (for logging)
func GetProtectionReason(ipStr string) string {
	// Check specific protected IPs
	switch ipStr {
	case "192.168.1.13":
		return "Sophos XGS WAN interface"
	case "192.168.1.1":
		return "Sophos XGS gateway"
	case "0.0.0.0", "127.0.0.1":
		return "Loopback/Invalid"
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	// Check networks
	if ip.IsLoopback() {
		return "Loopback address"
	}
	if ip.IsPrivate() {
		return "Private/Internal network"
	}
	if ip.IsLinkLocalUnicast() {
		return "Link-local address"
	}

	for _, network := range parsedProtectedNetworks {
		if network.Contains(ip) {
			return fmt.Sprintf("Protected network %s", network.String())
		}
	}

	return ""
}

// WAFServersRepository interface for country policy lookup
type WAFServersRepository interface {
	GetByHostname(ctx context.Context, hostname string) (*entity.WAFMonitoredServer, error)
}

// GeoIPProvider interface for IP country lookup
type GeoIPProvider interface {
	Lookup(ctx context.Context, ip string) (*entity.GeoLocation, error)
}

// GeoZoneRepository interface for global GeoZone settings
// v3.57.101: Added for fallback when WAF server has no specific policy
type GeoZoneRepository interface {
	GetGeoZoneConfig() (*entity.GeoZoneConfig, error)
}

// PendingBansRepository interface for pending ban approvals
// v3.57.113: Added for Authorized Countries pending approval flow
// v3.57.115: Added UpdatePendingBanEventCount to fix duplicate entries bug
type PendingBansRepository interface {
	CreatePendingBan(ctx context.Context, ban *entity.PendingBan) error
	GetPendingBanByIP(ctx context.Context, ip string) (*entity.PendingBan, error)
	UpdatePendingBanEventCount(ctx context.Context, ip string, newEventCount int) error
}

// FalsePositiveDetector interface for detecting FP patterns (v3.57.118)
type FalsePositiveDetector interface {
	DetectFalsePositivePattern(ctx context.Context, ip string, threshold int) (*clickhouse.FalsePositivePattern, error)
}

// Engine is the Detect2Ban detection engine
type Engine struct {
	scenarios       []*Scenario
	eventsRepo      *clickhouse.EventsRepository
	bansService     *bans.Service
	threatsService  *threats.Service
	wafServersRepo  WAFServersRepository  // v3.57: WAF server country policy
	geoZoneRepo     GeoZoneRepository     // v3.57.101: Global GeoZone settings fallback
	pendingBansRepo PendingBansRepository // v3.57.113: Pending approvals for authorized countries
	geoIPProvider   GeoIPProvider         // v3.57: GeoIP for country lookup
	fpDetector      FalsePositiveDetector // v3.57.118: False positive pattern detector
	mu              sync.RWMutex
	running         bool
	stopCh          chan struct{}
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

// SetWAFServersRepo sets the WAF servers repository for country policy lookup (v3.57)
func (e *Engine) SetWAFServersRepo(repo WAFServersRepository) {
	e.wafServersRepo = repo
}

// SetGeoIPProvider sets the GeoIP provider for country lookup (v3.57)
func (e *Engine) SetGeoIPProvider(provider GeoIPProvider) {
	e.geoIPProvider = provider
}

// SetGeoZoneRepo sets the GeoZone repository for global settings fallback (v3.57.101)
func (e *Engine) SetGeoZoneRepo(repo GeoZoneRepository) {
	e.geoZoneRepo = repo
}

// SetPendingBansRepo sets the pending bans repository for approval flow (v3.57.113)
func (e *Engine) SetPendingBansRepo(repo PendingBansRepository) {
	e.pendingBansRepo = repo
}

// SetFalsePositiveDetector sets the FP detector for pattern detection (v3.57.118)
func (e *Engine) SetFalsePositiveDetector(detector FalsePositiveDetector) {
	e.fpDetector = detector
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
	Hostname   string // v3.57: Target hostname for country policy
	EventCount uint64
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
		// v3.57: Also scan hostname for country policy
		if err := rows.Scan(&match.IP, &match.Hostname, &match.EventCount, &match.FirstEvent, &match.LastEvent); err != nil {
			continue
		}

		if match.EventCount >= uint64(scenario.Aggregation.Threshold) {
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

	// v3.57: Include hostname for country policy lookup
	// anyLast gets the most recent hostname for each IP
	query := fmt.Sprintf(`
		SELECT
			%s as ip,
			anyLast(hostname) as target_hostname,
			count() as event_count,
			min(timestamp) as first_event,
			max(timestamp) as last_event
		FROM vigilance_x.events
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

	// CRITICAL: Check if IP is protected (local/internal/infrastructure)
	// Detect2Ban only targets EXTERNAL threats - never ban internal IPs
	if IsProtectedIP(match.IP) {
		reason := GetProtectionReason(match.IP)
		log.Printf("[DETECT2BAN] PROTECTED IP %s - %s (scenario: %s, events: %d) - SKIPPING BAN",
			match.IP, reason, scenario.Name, match.EventCount)
		return
	}

	// v3.57.101: Check country policy - WAF server rules override global settings
	// Priority: WAF server policy > Global GeoZone settings
	// v3.57.113: Authorized countries (FR, LU) go to pending_approval instead of auto-ban
	if e.geoIPProvider != nil {
		// First, try WAF server-specific policy (if server has policy enabled)
		var useGlobalSettings = true
		if e.wafServersRepo != nil && match.Hostname != "" {
			server, err := e.wafServersRepo.GetByHostname(ctx, match.Hostname)
			if err == nil && server != nil && server.PolicyEnabled {
				// Server has its own policy - use it exclusively (no fallback to global)
				useGlobalSettings = false
				geoInfo, err := e.geoIPProvider.Lookup(ctx, match.IP)
				if err == nil && geoInfo != nil && geoInfo.CountryCode != "" {
					policyResult := server.CheckCountryPolicy(geoInfo.CountryCode)
					if policyResult.ShouldBan {
						log.Printf("[DETECT2BAN] Server policy triggered for IP %s (country: %s, hostname: %s, policy: %s)",
							match.IP, geoInfo.CountryCode, match.Hostname, policyResult.PolicyHit)
						e.executeCountryPolicyBan(ctx, match, policyResult.BanReason)
						return
					}
					// v3.57.113: Authorized country detected (FR, LU in whitelist)
					// These IPs require manual admin approval before banning
					if policyResult.RequireApproval && policyResult.IsAuthorizedCountry {
						log.Printf("[DETECT2BAN] Authorized country IP %s (country: %s, hostname: %s) - creating pending approval",
							match.IP, geoInfo.CountryCode, match.Hostname)
						e.createPendingApproval(ctx, match, geoInfo.CountryCode, server.Hostname)
						return
					}
				}
			}
		}

		// Fallback to global GeoZone settings if no server-specific policy
		if useGlobalSettings && e.geoZoneRepo != nil {
			geoZoneConfig, err := e.geoZoneRepo.GetGeoZoneConfig()
			if err == nil && geoZoneConfig != nil && geoZoneConfig.Enabled {
				geoInfo, err := e.geoIPProvider.Lookup(ctx, match.IP)
				if err == nil && geoInfo != nil && geoInfo.CountryCode != "" {
					zone := geoZoneConfig.ClassifyCountry(geoInfo.CountryCode)
					if zone == entity.GeoZoneHostile {
						// Hostile country - immediate ban
						banReason := fmt.Sprintf("GeoZone: Country %s is in hostile list", geoInfo.CountryCode)
						log.Printf("[DETECT2BAN] Global GeoZone hostile country triggered for IP %s (country: %s)",
							match.IP, geoInfo.CountryCode)
						e.executeCountryPolicyBan(ctx, match, banReason)
						return
					}
					// For authorized/neutral zones, let normal D2B flow continue
				}
			}
		}
	}

	// Check if already banned
	existingBan, err := e.bansService.GetBan(ctx, match.IP)
	if err == nil && existingBan != nil {
		if existingBan.Status == entity.BanStatusActive || existingBan.Status == entity.BanStatusPermanent {
			log.Printf("[DETECT2BAN] IP %s already banned, skipping", match.IP)
			return
		}

		// Check if IP has immunity (from manual unban with immunity)
		if existingBan.IsImmune() {
			log.Printf("[DETECT2BAN] IP %s has immunity until %v, skipping auto-ban",
				match.IP, existingBan.ImmuneUntil.Format("2006-01-02 15:04:05"))
			return
		}

		// v3.53.106: Check if immunity just expired - only count events AFTER immunity ended
		// This prevents banning based on events that occurred during the immunity period
		if existingBan.ImmuneUntil != nil && !existingBan.IsImmune() {
			immuneEnded := *existingBan.ImmuneUntil
			// Parse scenario window
			window, _ := time.ParseDuration(scenario.Aggregation.Window)
			if window == 0 {
				window = 5 * time.Minute
			}

			// If immunity ended within the scenario window, recount events after immunity
			if time.Since(immuneEnded) < window {
				eventsAfterImmunity, err := e.countEventsAfter(ctx, scenario, match.IP, immuneEnded)
				if err != nil {
					log.Printf("[DETECT2BAN] Error counting events after immunity for %s: %v", match.IP, err)
					return
				}

				if eventsAfterImmunity < uint64(scenario.Aggregation.Threshold) {
					log.Printf("[DETECT2BAN] IP %s: only %d events after immunity ended at %v (threshold: %d), skipping ban",
						match.IP, eventsAfterImmunity, immuneEnded.Format("15:04:05"), scenario.Aggregation.Threshold)
					return
				}

				log.Printf("[DETECT2BAN] IP %s: %d events after immunity ended, proceeding with ban",
					match.IP, eventsAfterImmunity)
			}
		}
	}

	// v3.57.118: Check for false positive patterns before banning
	// If same IP triggers 10+ identical attacks (same rule_id + same URI), it's likely a FP
	// Examples: Mattermost client repeatedly hitting strict ModSec rules
	if e.fpDetector != nil && scenario.Name == "waf_attacks" {
		fpPattern, err := e.fpDetector.DetectFalsePositivePattern(ctx, match.IP, entity.FalsePositiveThreshold)
		if err == nil && fpPattern != nil {
			log.Printf("[DETECT2BAN] False positive pattern detected for IP %s (rule: %s, uri: %s, count: %d)",
				match.IP, fpPattern.RuleID, fpPattern.URI, fpPattern.MatchCount)
			e.createFalsePositiveApproval(ctx, match, fpPattern)
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

// executeCountryPolicyBan bans an IP based on country policy (v3.57)
func (e *Engine) executeCountryPolicyBan(ctx context.Context, match ScenarioMatch, banReason string) {
	// Country policy bans are 24h by default
	durationDays := 1

	req := &entity.BanRequest{
		IP:           match.IP,
		Reason:       banReason,
		DurationDays: &durationDays,
		Permanent:    false,
		TriggerRule:  "country_policy",
		PerformedBy:  "detect2ban",
	}

	ban, err := e.bansService.BanIP(ctx, req)
	if err != nil {
		log.Printf("[DETECT2BAN] Failed to ban %s (country policy): %v", match.IP, err)
		return
	}

	log.Printf("[DETECT2BAN] Banned IP %s via country policy (status: %s, expires: %v)",
		match.IP, ban.Status, ban.ExpiresAt)
}

// createPendingApproval creates a pending approval entry for authorized country IPs
// v3.57.113: IPs from whitelisted countries (FR, LU) require manual admin approval
// v3.57.114: Check for existing pending entry to avoid duplicates
func (e *Engine) createPendingApproval(ctx context.Context, match ScenarioMatch, countryCode, hostname string) {
	if e.pendingBansRepo == nil {
		log.Printf("[DETECT2BAN] Pending bans repository not configured, skipping pending approval for %s", match.IP)
		return
	}

	// v3.57.114: Check if pending approval already exists for this IP
	// v3.57.115: Update existing entry instead of creating duplicate
	// v3.57.116: Fixed ClickHouse type compatibility (int32/uint32)
	existing, _ := e.pendingBansRepo.GetPendingBanByIP(ctx, match.IP)
	if existing != nil && existing.Status == "pending" {
		// Update event count if new count is higher (IP is still attacking)
		// v3.57.116: Fixed type comparison - existing.EventCount is now uint32
		if match.EventCount > uint64(existing.EventCount) {
			if err := e.pendingBansRepo.UpdatePendingBanEventCount(ctx, match.IP, int(match.EventCount)); err != nil {
				log.Printf("[DETECT2BAN] Failed to update pending ban event count for %s: %v", match.IP, err)
			} else {
				log.Printf("[DETECT2BAN] Updated pending approval for IP %s (events: %d -> %d)",
					match.IP, existing.EventCount, match.EventCount)
			}
		}
		return
	}

	// Get threat score if available
	var threatScore int
	var threatSources []string
	if e.threatsService != nil {
		result, err := e.threatsService.CheckIP(ctx, match.IP)
		if err == nil && result != nil {
			threatScore = result.AggregatedScore
			for _, src := range result.Sources {
				threatSources = append(threatSources, src.Provider)
			}
		}
	}

	pendingBan := &entity.PendingBan{
		IP:            match.IP,
		Country:       countryCode,
		GeoZone:       entity.GeoZoneAuthorized,
		ThreatScore:   int32(threatScore), // v3.57.116: Cast to int32 for ClickHouse
		ThreatSources: threatSources,
		EventCount:    uint32(match.EventCount), // v3.57.116: Cast to uint32 for ClickHouse
		FirstEvent:    time.Now(),
		LastEvent:     time.Now(),
		TriggerRule:   "authorized_country_waf",
		Reason:        fmt.Sprintf("WAF attack from authorized country %s on %s (%d events) - requires approval", countryCode, hostname, match.EventCount),
		Status:        "pending",
	}

	if err := e.pendingBansRepo.CreatePendingBan(ctx, pendingBan); err != nil {
		log.Printf("[DETECT2BAN] Failed to create pending approval for %s: %v", match.IP, err)
		return
	}

	log.Printf("[DETECT2BAN] Created pending approval for IP %s (country: %s, hostname: %s, threat_score: %d, events: %d)",
		match.IP, countryCode, hostname, threatScore, match.EventCount)
}

// createFalsePositiveApproval creates a pending approval for potential false positive IPs
// v3.57.118: Detected when same IP triggers 10+ identical attacks (same rule_id + same URI)
func (e *Engine) createFalsePositiveApproval(ctx context.Context, match ScenarioMatch, fpPattern *clickhouse.FalsePositivePattern) {
	if e.pendingBansRepo == nil {
		log.Printf("[DETECT2BAN] Pending bans repository not configured, skipping FP approval for %s", match.IP)
		return
	}

	// Check if pending approval already exists for this IP
	existing, _ := e.pendingBansRepo.GetPendingBanByIP(ctx, match.IP)
	if existing != nil && existing.Status == "pending" {
		// Update event count if new count is higher
		if match.EventCount > uint64(existing.EventCount) {
			if err := e.pendingBansRepo.UpdatePendingBanEventCount(ctx, match.IP, int(match.EventCount)); err != nil {
				log.Printf("[DETECT2BAN] Failed to update FP pending ban event count for %s: %v", match.IP, err)
			} else {
				log.Printf("[DETECT2BAN] Updated FP pending approval for IP %s (events: %d -> %d)",
					match.IP, existing.EventCount, match.EventCount)
			}
		}
		return
	}

	// Get country code via GeoIP
	countryCode := ""
	if e.geoIPProvider != nil {
		geoInfo, err := e.geoIPProvider.Lookup(ctx, match.IP)
		if err == nil && geoInfo != nil {
			countryCode = geoInfo.CountryCode
		}
	}

	// Get threat score if available
	var threatScore int
	var threatSources []string
	if e.threatsService != nil {
		result, err := e.threatsService.CheckIP(ctx, match.IP)
		if err == nil && result != nil {
			threatScore = result.AggregatedScore
			for _, src := range result.Sources {
				threatSources = append(threatSources, src.Provider)
			}
		}
	}

	pendingBan := &entity.PendingBan{
		IP:            match.IP,
		Country:       countryCode,
		GeoZone:       entity.GeoZoneNeutral, // FP is not zone-based
		ThreatScore:   int32(threatScore),
		ThreatSources: threatSources,
		EventCount:    uint32(match.EventCount),
		FirstEvent:    time.Now(),
		LastEvent:     time.Now(),
		TriggerRule:   "false_positive_detection",
		Reason:        fmt.Sprintf("Potential false positive: %d identical attacks (rule %s on %s) - requires review", fpPattern.MatchCount, fpPattern.RuleID, fpPattern.URI),
		Status:        "pending",
		// v3.57.118: FP-specific fields
		PendingType:  entity.PendingTypeFalsePositive,
		FPRuleID:     fpPattern.RuleID,
		FPURI:        fpPattern.URI,
		FPHostname:   fpPattern.Hostname,
		FPMatchCount: uint32(fpPattern.MatchCount),
	}

	if err := e.pendingBansRepo.CreatePendingBan(ctx, pendingBan); err != nil {
		log.Printf("[DETECT2BAN] Failed to create FP pending approval for %s: %v", match.IP, err)
		return
	}

	log.Printf("[DETECT2BAN] Created FP pending approval for IP %s (rule: %s, uri: %s, matches: %d, threat_score: %d)",
		match.IP, fpPattern.RuleID, fpPattern.URI, fpPattern.MatchCount, threatScore)
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

// countEventsAfter counts events for a specific IP after a given timestamp
// Used to verify if there are enough events AFTER immunity period ended
func (e *Engine) countEventsAfter(ctx context.Context, scenario *Scenario, ip string, after time.Time) (uint64, error) {
	// Build WHERE clause starting with timestamp > immunity end
	whereClause := fmt.Sprintf("timestamp > toDateTime('%s')", after.UTC().Format("2006-01-02 15:04:05"))

	// Add IP filter
	groupBy := scenario.Aggregation.GroupBy
	if groupBy == "" {
		groupBy = "src_ip"
	}
	whereClause += fmt.Sprintf(" AND %s = '%s'", groupBy, ip)

	// Add scenario conditions
	for _, cond := range scenario.Conditions {
		clause := e.conditionToSQL(cond)
		if clause != "" {
			whereClause += " AND " + clause
		}
	}

	query := fmt.Sprintf("SELECT count() FROM vigilance_x.events WHERE %s", whereClause)

	rows, err := e.eventsRepo.RawQuery(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("count events after: %w", err)
	}
	defer rows.Close()

	var count uint64
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			return 0, fmt.Errorf("scan count: %w", err)
		}
	}

	return count, nil
}
