package notifications

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kr1s57/vigilancex/internal/adapter/external/smtp"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// Service handles notification business logic
type Service struct {
	smtpClient   *smtp.Client
	logger       *slog.Logger
	settings     *entity.NotificationSettings
	settingsPath string
	mu           sync.RWMutex
	scheduler    *Scheduler
}

// UpdateSMTPClient updates the SMTP client configuration (hot-reload)
func (s *Service) UpdateSMTPClient(client *smtp.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smtpClient = client
	s.settings.SMTPConfigured = client != nil && client.IsConfigured()
	s.logger.Info("SMTP client updated", "configured", s.settings.SMTPConfigured)
}

// UpdateSMTPConfig updates and persists the SMTP configuration
func (s *Service) UpdateSMTPConfig(config *entity.SMTPConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store config in settings for persistence
	s.settings.SMTPConfig = config

	// Create new SMTP client with the config
	if config != nil && config.Host != "" {
		s.smtpClient = smtp.NewClient(smtp.Config{
			Host:       config.Host,
			Port:       config.Port,
			Security:   config.Security,
			FromEmail:  config.FromEmail,
			Username:   config.Username,
			Password:   config.Password,
			Recipients: config.Recipients,
		}, s.logger)
		s.settings.SMTPConfigured = s.smtpClient.IsConfigured()
	} else {
		s.smtpClient = nil
		s.settings.SMTPConfigured = false
	}

	// Save to disk for persistence across restarts
	if err := s.saveSettings(); err != nil {
		return fmt.Errorf("save SMTP config: %w", err)
	}

	s.logger.Info("SMTP config updated and persisted",
		"host", config.Host,
		"port", config.Port,
		"configured", s.settings.SMTPConfigured)

	return nil
}

// GetSMTPConfig returns the current SMTP configuration (without password)
func (s *Service) GetSMTPConfig() *entity.SMTPConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.settings.SMTPConfig == nil {
		return nil
	}

	// Return config without password for security
	return &entity.SMTPConfig{
		Host:       s.settings.SMTPConfig.Host,
		Port:       s.settings.SMTPConfig.Port,
		Security:   s.settings.SMTPConfig.Security,
		FromEmail:  s.settings.SMTPConfig.FromEmail,
		Username:   s.settings.SMTPConfig.Username,
		Password:   "", // Don't expose password
		Recipients: s.settings.SMTPConfig.Recipients,
	}
}

// NewService creates a new notification service
func NewService(smtpClient *smtp.Client, logger *slog.Logger) *Service {
	s := &Service{
		smtpClient:   smtpClient,
		logger:       logger,
		settings:     entity.DefaultNotificationSettings(),
		settingsPath: "/app/config/notification_settings.json",
	}

	// Load settings from disk (includes SMTP config if previously saved)
	s.loadSettings()

	// If SMTP config was persisted and no client provided from env, create one from saved config
	if smtpClient == nil && s.settings.SMTPConfig != nil && s.settings.SMTPConfig.Host != "" {
		logger.Info("Loading SMTP config from persisted settings",
			"host", s.settings.SMTPConfig.Host,
			"port", s.settings.SMTPConfig.Port)
		s.smtpClient = smtp.NewClient(smtp.Config{
			Host:       s.settings.SMTPConfig.Host,
			Port:       s.settings.SMTPConfig.Port,
			Security:   s.settings.SMTPConfig.Security,
			FromEmail:  s.settings.SMTPConfig.FromEmail,
			Username:   s.settings.SMTPConfig.Username,
			Password:   s.settings.SMTPConfig.Password,
			Recipients: s.settings.SMTPConfig.Recipients,
		}, logger)
	}

	// Update SMTP configured status
	s.settings.SMTPConfigured = s.smtpClient != nil && s.smtpClient.IsConfigured()

	return s
}

// SetScheduler sets the scheduler reference for the service
func (s *Service) SetScheduler(scheduler *Scheduler) {
	s.scheduler = scheduler
}

// GetSettings returns current notification settings
func (s *Service) GetSettings() *entity.NotificationSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Update SMTP status
	settings := *s.settings
	settings.SMTPConfigured = s.smtpClient != nil && s.smtpClient.IsConfigured()

	return &settings
}

// UpdateSettings updates notification settings
func (s *Service) UpdateSettings(settings *entity.NotificationSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Preserve SMTP configured status
	settings.SMTPConfigured = s.smtpClient != nil && s.smtpClient.IsConfigured()

	s.settings = settings

	// Save to disk
	if err := s.saveSettings(); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}

	// Reschedule reports if scheduler exists
	if s.scheduler != nil {
		s.scheduler.RescheduleReports(settings)
	}

	s.logger.Info("Notification settings updated",
		"daily_enabled", settings.DailyReportEnabled,
		"weekly_enabled", settings.WeeklyReportEnabled,
		"monthly_enabled", settings.MonthlyReportEnabled,
	)

	return nil
}

// MergeAndUpdateSettings atomically merges partial updates with current settings
func (s *Service) MergeAndUpdateSettings(updates map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Apply updates to current settings atomically
	if v, ok := updates["daily_report_enabled"].(bool); ok {
		s.settings.DailyReportEnabled = v
	}
	if v, ok := updates["daily_report_time"].(string); ok {
		s.settings.DailyReportTime = v
	}
	if v, ok := updates["weekly_report_enabled"].(bool); ok {
		s.settings.WeeklyReportEnabled = v
	}
	if v, ok := updates["weekly_report_day"].(float64); ok {
		s.settings.WeeklyReportDay = int(v)
	}
	if v, ok := updates["weekly_report_time"].(string); ok {
		s.settings.WeeklyReportTime = v
	}
	if v, ok := updates["monthly_report_enabled"].(bool); ok {
		s.settings.MonthlyReportEnabled = v
	}
	if v, ok := updates["monthly_report_day"].(float64); ok {
		s.settings.MonthlyReportDay = int(v)
	}
	if v, ok := updates["monthly_report_time"].(string); ok {
		s.settings.MonthlyReportTime = v
	}
	if v, ok := updates["waf_detection_enabled"].(bool); ok {
		s.settings.WAFDetectionEnabled = v
	}
	if v, ok := updates["waf_blocked_enabled"].(bool); ok {
		s.settings.WAFBlockedEnabled = v
	}
	if v, ok := updates["new_ban_enabled"].(bool); ok {
		s.settings.NewBanEnabled = v
	}
	if v, ok := updates["critical_alert_enabled"].(bool); ok {
		s.settings.CriticalAlertEnabled = v
	}
	if v, ok := updates["min_severity_level"].(string); ok {
		s.settings.MinSeverityLevel = v
	}

	// Preserve SMTP configured status
	s.settings.SMTPConfigured = s.smtpClient != nil && s.smtpClient.IsConfigured()

	// Save to disk
	if err := s.saveSettings(); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}

	// Reschedule reports if scheduler exists
	if s.scheduler != nil {
		s.scheduler.RescheduleReports(s.settings)
	}

	s.logger.Info("[ATOMIC] Notification settings merged and saved",
		"daily", s.settings.DailyReportEnabled,
		"weekly", s.settings.WeeklyReportEnabled,
		"monthly", s.settings.MonthlyReportEnabled,
		"waf_detection", s.settings.WAFDetectionEnabled,
		"waf_blocked", s.settings.WAFBlockedEnabled,
		"new_ban", s.settings.NewBanEnabled,
		"critical", s.settings.CriticalAlertEnabled,
	)

	return nil
}

// SendTestEmail sends a test email
func (s *Service) SendTestEmail(ctx context.Context, recipients []string) error {
	if s.smtpClient == nil || !s.smtpClient.IsConfigured() {
		return fmt.Errorf("SMTP not configured")
	}

	if len(recipients) == 0 {
		recipients = s.smtpClient.GetRecipients()
	}

	if len(recipients) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	subject, textBody, htmlBody := smtp.RenderTestEmail()

	notif := &entity.EmailNotification{
		ID:         uuid.New().String(),
		Type:       "test",
		Subject:    subject,
		TextBody:   textBody,
		HTMLBody:   htmlBody,
		Recipients: recipients,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}

	if err := s.smtpClient.SendEmail(ctx, notif); err != nil {
		notif.Status = "failed"
		notif.Error = err.Error()
		return fmt.Errorf("send test email: %w", err)
	}

	now := time.Now()
	notif.Status = "sent"
	notif.SentAt = &now

	s.logger.Info("Test email sent", "recipients", recipients)
	return nil
}

// SendDailyReport sends the daily security report
func (s *Service) SendDailyReport(ctx context.Context, data *entity.ReportData) error {
	if s.smtpClient == nil || !s.smtpClient.IsConfigured() {
		return fmt.Errorf("SMTP not configured")
	}

	s.mu.RLock()
	if !s.settings.DailyReportEnabled {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	recipients := s.smtpClient.GetRecipients()
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	subject, textBody, htmlBody := smtp.RenderDailyReport(data)

	notif := &entity.EmailNotification{
		ID:         uuid.New().String(),
		Type:       "report_daily",
		Subject:    subject,
		TextBody:   textBody,
		HTMLBody:   htmlBody,
		Recipients: recipients,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}

	if err := s.smtpClient.SendEmail(ctx, notif); err != nil {
		s.logger.Error("Failed to send daily report", "error", err)
		return err
	}

	s.logger.Info("Daily report sent", "recipients", len(recipients))
	return nil
}

// SendWeeklyReport sends the weekly security report
func (s *Service) SendWeeklyReport(ctx context.Context, data *entity.ReportData) error {
	if s.smtpClient == nil || !s.smtpClient.IsConfigured() {
		return fmt.Errorf("SMTP not configured")
	}

	s.mu.RLock()
	if !s.settings.WeeklyReportEnabled {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	recipients := s.smtpClient.GetRecipients()
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	subject, textBody, htmlBody := smtp.RenderWeeklyReport(data)

	notif := &entity.EmailNotification{
		ID:         uuid.New().String(),
		Type:       "report_weekly",
		Subject:    subject,
		TextBody:   textBody,
		HTMLBody:   htmlBody,
		Recipients: recipients,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}

	if err := s.smtpClient.SendEmail(ctx, notif); err != nil {
		s.logger.Error("Failed to send weekly report", "error", err)
		return err
	}

	s.logger.Info("Weekly report sent", "recipients", len(recipients))
	return nil
}

// SendMonthlyReport sends the monthly security report
func (s *Service) SendMonthlyReport(ctx context.Context, data *entity.ReportData) error {
	if s.smtpClient == nil || !s.smtpClient.IsConfigured() {
		return fmt.Errorf("SMTP not configured")
	}

	s.mu.RLock()
	if !s.settings.MonthlyReportEnabled {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	recipients := s.smtpClient.GetRecipients()
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	subject, textBody, htmlBody := smtp.RenderMonthlyReport(data)

	notif := &entity.EmailNotification{
		ID:         uuid.New().String(),
		Type:       "report_monthly",
		Subject:    subject,
		TextBody:   textBody,
		HTMLBody:   htmlBody,
		Recipients: recipients,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}

	if err := s.smtpClient.SendEmail(ctx, notif); err != nil {
		s.logger.Error("Failed to send monthly report", "error", err)
		return err
	}

	s.logger.Info("Monthly report sent", "recipients", len(recipients))
	return nil
}

// SendWAFAlert sends a WAF detection/blocked alert
func (s *Service) SendWAFAlert(ctx context.Context, data *entity.AlertData) error {
	if s.smtpClient == nil || !s.smtpClient.IsConfigured() {
		return fmt.Errorf("SMTP not configured")
	}

	s.mu.RLock()
	// Check if this alert type is enabled
	switch data.AlertType {
	case "waf_detection":
		if !s.settings.WAFDetectionEnabled {
			s.mu.RUnlock()
			return nil
		}
	case "waf_blocked":
		if !s.settings.WAFBlockedEnabled {
			s.mu.RUnlock()
			return nil
		}
	}

	// Check severity threshold
	if !s.meetsThreshold(data.Severity) {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	recipients := s.smtpClient.GetRecipients()
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	subject, textBody, htmlBody := smtp.RenderWAFAlert(data)

	notif := &entity.EmailNotification{
		ID:         uuid.New().String(),
		Type:       "alert_waf",
		Subject:    subject,
		TextBody:   textBody,
		HTMLBody:   htmlBody,
		Recipients: recipients,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}

	if err := s.smtpClient.SendEmail(ctx, notif); err != nil {
		s.logger.Error("Failed to send WAF alert", "error", err)
		return err
	}

	s.logger.Info("WAF alert sent", "type", data.AlertType, "source_ip", data.SourceIP)
	return nil
}

// SendBanAlert sends a new ban alert
func (s *Service) SendBanAlert(ctx context.Context, data *entity.AlertData) error {
	if s.smtpClient == nil || !s.smtpClient.IsConfigured() {
		return fmt.Errorf("SMTP not configured")
	}

	s.mu.RLock()
	if !s.settings.NewBanEnabled {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	recipients := s.smtpClient.GetRecipients()
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	subject, textBody, htmlBody := smtp.RenderBanAlert(data)

	notif := &entity.EmailNotification{
		ID:         uuid.New().String(),
		Type:       "alert_ban",
		Subject:    subject,
		TextBody:   textBody,
		HTMLBody:   htmlBody,
		Recipients: recipients,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}

	if err := s.smtpClient.SendEmail(ctx, notif); err != nil {
		s.logger.Error("Failed to send ban alert", "error", err)
		return err
	}

	s.logger.Info("Ban alert sent", "source_ip", data.SourceIP)
	return nil
}

// SendCriticalAlert sends a critical security alert
func (s *Service) SendCriticalAlert(ctx context.Context, data *entity.AlertData) error {
	if s.smtpClient == nil || !s.smtpClient.IsConfigured() {
		return fmt.Errorf("SMTP not configured")
	}

	s.mu.RLock()
	if !s.settings.CriticalAlertEnabled {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	recipients := s.smtpClient.GetRecipients()
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	subject, textBody, htmlBody := smtp.RenderCriticalAlert(data)

	notif := &entity.EmailNotification{
		ID:         uuid.New().String(),
		Type:       "alert_critical",
		Subject:    subject,
		TextBody:   textBody,
		HTMLBody:   htmlBody,
		Recipients: recipients,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}

	if err := s.smtpClient.SendEmail(ctx, notif); err != nil {
		s.logger.Error("Failed to send critical alert", "error", err)
		return err
	}

	s.logger.Info("Critical alert sent", "source_ip", data.SourceIP, "severity", data.Severity)
	return nil
}

// meetsThreshold checks if the severity meets the minimum threshold
func (s *Service) meetsThreshold(severity string) bool {
	severityOrder := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	minLevel := severityOrder[strings.ToLower(s.settings.MinSeverityLevel)]
	eventLevel := severityOrder[strings.ToLower(severity)]

	return eventLevel >= minLevel
}

// loadSettings loads settings from disk
func (s *Service) loadSettings() {
	data, err := os.ReadFile(s.settingsPath)
	if err != nil {
		s.logger.Debug("No saved notification settings found, using defaults")
		return
	}

	var settings entity.NotificationSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		s.logger.Warn("Failed to parse notification settings", "error", err)
		return
	}

	s.settings = &settings
	s.logger.Info("Loaded notification settings from disk")
}

// saveSettings saves settings to disk
func (s *Service) saveSettings() error {
	// Ensure directory exists
	dir := filepath.Dir(s.settingsPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create settings dir: %w", err)
	}

	data, err := json.MarshalIndent(s.settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}

	if err := os.WriteFile(s.settingsPath, data, 0600); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}

	return nil
}

// IsSMTPConfigured returns whether SMTP is configured
func (s *Service) IsSMTPConfigured() bool {
	return s.smtpClient != nil && s.smtpClient.IsConfigured()
}

// GetSMTPHost returns the configured SMTP host
func (s *Service) GetSMTPHost() string {
	if s.smtpClient == nil {
		return ""
	}
	return s.smtpClient.GetHost()
}

// SendEmailWithAttachment sends an email with optional attachments (for reports)
func (s *Service) SendEmailWithAttachment(ctx context.Context, notif *entity.EmailNotification) error {
	if s.smtpClient == nil || !s.smtpClient.IsConfigured() {
		return fmt.Errorf("SMTP not configured")
	}

	if err := s.smtpClient.SendEmail(ctx, notif); err != nil {
		s.logger.Error("Failed to send email with attachment", "error", err, "type", notif.Type)
		return err
	}

	s.logger.Info("Email with attachment sent", "type", notif.Type, "recipients", len(notif.Recipients))
	return nil
}
