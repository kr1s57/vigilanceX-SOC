package notifications

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// TriggerHandler handles real-time event triggers for notifications
type TriggerHandler struct {
	service *Service
	logger  *slog.Logger

	// Rate limiting to prevent email flooding
	lastWAFAlert      time.Time
	lastBanAlert      time.Time
	lastCriticalAlert time.Time
	alertCooldown     time.Duration
	mu                sync.Mutex
}

// NewTriggerHandler creates a new trigger handler
func NewTriggerHandler(service *Service, logger *slog.Logger) *TriggerHandler {
	return &TriggerHandler{
		service:       service,
		logger:        logger,
		alertCooldown: 5 * time.Minute, // Minimum 5 minutes between similar alerts
	}
}

// OnWAFDetection handles WAF detection events
func (t *TriggerHandler) OnWAFDetection(ctx context.Context, event *entity.AlertData) {
	t.mu.Lock()
	if time.Since(t.lastWAFAlert) < t.alertCooldown {
		t.mu.Unlock()
		t.logger.Debug("WAF alert skipped (cooldown)", "source_ip", event.SourceIP)
		return
	}
	t.lastWAFAlert = time.Now()
	t.mu.Unlock()

	event.AlertType = "waf_detection"

	if err := t.service.SendWAFAlert(ctx, event); err != nil {
		t.logger.Error("Failed to send WAF detection alert", "error", err, "source_ip", event.SourceIP)
	}
}

// OnWAFBlocked handles WAF blocked events
func (t *TriggerHandler) OnWAFBlocked(ctx context.Context, event *entity.AlertData) {
	t.mu.Lock()
	if time.Since(t.lastWAFAlert) < t.alertCooldown {
		t.mu.Unlock()
		t.logger.Debug("WAF blocked alert skipped (cooldown)", "source_ip", event.SourceIP)
		return
	}
	t.lastWAFAlert = time.Now()
	t.mu.Unlock()

	event.AlertType = "waf_blocked"

	if err := t.service.SendWAFAlert(ctx, event); err != nil {
		t.logger.Error("Failed to send WAF blocked alert", "error", err, "source_ip", event.SourceIP)
	}
}

// OnNewBan handles new IP ban events
func (t *TriggerHandler) OnNewBan(ctx context.Context, ip string, reason string, score int) {
	t.mu.Lock()
	if time.Since(t.lastBanAlert) < t.alertCooldown {
		t.mu.Unlock()
		t.logger.Debug("Ban alert skipped (cooldown)", "ip", ip)
		return
	}
	t.lastBanAlert = time.Now()
	t.mu.Unlock()

	event := &entity.AlertData{
		AlertType:   "new_ban",
		Timestamp:   time.Now(),
		SourceIP:    ip,
		ThreatScore: score,
		Details:     reason,
		Severity:    scoreSeverity(score),
	}

	if err := t.service.SendBanAlert(ctx, event); err != nil {
		t.logger.Error("Failed to send ban alert", "error", err, "ip", ip)
	}
}

// OnCriticalEvent handles critical security events
func (t *TriggerHandler) OnCriticalEvent(ctx context.Context, event *entity.AlertData) {
	t.mu.Lock()
	if time.Since(t.lastCriticalAlert) < t.alertCooldown {
		t.mu.Unlock()
		t.logger.Debug("Critical alert skipped (cooldown)", "source_ip", event.SourceIP)
		return
	}
	t.lastCriticalAlert = time.Now()
	t.mu.Unlock()

	event.AlertType = "critical"
	if event.Severity == "" {
		event.Severity = "critical"
	}

	if err := t.service.SendCriticalAlert(ctx, event); err != nil {
		t.logger.Error("Failed to send critical alert", "error", err, "source_ip", event.SourceIP)
	}
}

// ProcessModSecEvent processes a ModSecurity event and triggers alerts if needed
func (t *TriggerHandler) ProcessModSecEvent(ctx context.Context, log *entity.ModSecLog) {
	settings := t.service.GetSettings()

	// Check if WAF alerts are enabled
	if !settings.WAFDetectionEnabled && !settings.WAFBlockedEnabled {
		return
	}

	// Check specific event IDs if configured
	if len(settings.SpecificEventIDs) > 0 {
		found := false
		for _, id := range settings.SpecificEventIDs {
			if log.RuleID == id {
				found = true
				break
			}
		}
		if !found {
			return
		}
	}

	// Convert severity string to level
	severity := "medium"
	switch log.RuleSeverity {
	case "CRITICAL", "0":
		severity = "critical"
	case "ERROR", "1", "2":
		severity = "high"
	case "WARNING", "3", "4":
		severity = "medium"
	default:
		severity = "low"
	}

	// Calculate threat score from total score
	threatScore := int(log.TotalScore)
	if threatScore > 100 {
		threatScore = 100
	}

	event := &entity.AlertData{
		Timestamp:   log.Timestamp,
		SourceIP:    log.SrcIP,
		Target:      log.URI,
		RuleID:      log.RuleID,
		RuleName:    log.RuleMsg,
		Details:     log.RuleData,
		Severity:    severity,
		ThreatScore: threatScore,
	}

	if log.IsBlocking && settings.WAFBlockedEnabled {
		t.OnWAFBlocked(ctx, event)
	} else if settings.WAFDetectionEnabled {
		t.OnWAFDetection(ctx, event)
	}
}

// SetCooldown sets the alert cooldown period
func (t *TriggerHandler) SetCooldown(duration time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.alertCooldown = duration
}

// scoreSeverity converts a threat score to severity level
func scoreSeverity(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}
