package entity

import "time"

// SMTPConfig holds SMTP server configuration
type SMTPConfig struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Security   string   `json:"security"` // tls, ssl, none
	FromEmail  string   `json:"from_email"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Recipients []string `json:"recipients"`
}

// NotificationSettings holds notification trigger settings
type NotificationSettings struct {
	// SMTP Status
	SMTPConfigured bool `json:"smtp_configured"`

	// SMTP Config (persisted) - v3.5
	SMTPConfig *SMTPConfig `json:"smtp_config,omitempty"`

	// Scheduled Reports
	DailyReportEnabled   bool     `json:"daily_report_enabled"`
	DailyReportTime      string   `json:"daily_report_time"` // HH:MM format
	WeeklyReportEnabled  bool     `json:"weekly_report_enabled"`
	WeeklyReportDay      int      `json:"weekly_report_day"`  // 0=Sun, 1=Mon, etc.
	WeeklyReportTime     string   `json:"weekly_report_time"` // HH:MM format
	MonthlyReportEnabled bool     `json:"monthly_report_enabled"`
	MonthlyReportDay     int      `json:"monthly_report_day"`  // 1-28
	MonthlyReportTime    string   `json:"monthly_report_time"` // HH:MM format
	ReportRecipients     []string `json:"report_recipients"`   // Email addresses for scheduled reports

	// Real-time Alerts
	WAFDetectionEnabled  bool `json:"waf_detection_enabled"`
	WAFBlockedEnabled    bool `json:"waf_blocked_enabled"`
	NewBanEnabled        bool `json:"new_ban_enabled"`
	CriticalAlertEnabled bool `json:"critical_alert_enabled"`

	// Severity Thresholds
	MinSeverityLevel string   `json:"min_severity_level"` // critical, high, medium, low
	SpecificEventIDs []string `json:"specific_event_ids"`
}

// DefaultNotificationSettings returns default notification settings
func DefaultNotificationSettings() *NotificationSettings {
	return &NotificationSettings{
		SMTPConfigured:       false,
		DailyReportEnabled:   false,
		DailyReportTime:      "08:00",
		WeeklyReportEnabled:  false,
		WeeklyReportDay:      1, // Monday
		WeeklyReportTime:     "08:00",
		MonthlyReportEnabled: false,
		MonthlyReportDay:     1,
		MonthlyReportTime:    "08:00",
		ReportRecipients:     []string{},
		WAFDetectionEnabled:  false,
		WAFBlockedEnabled:    false,
		NewBanEnabled:        false,
		CriticalAlertEnabled: true,
		MinSeverityLevel:     "critical",
		SpecificEventIDs:     []string{},
	}
}

// EmailAttachment represents a file attachment
type EmailAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        []byte `json:"-"` // Binary data, not serialized to JSON
}

// EmailNotification represents a single notification to send
type EmailNotification struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"` // report_daily, report_weekly, report_monthly, alert_waf, alert_ban, alert_critical
	Subject     string            `json:"subject"`
	TextBody    string            `json:"text_body"`
	HTMLBody    string            `json:"html_body"`
	Recipients  []string          `json:"recipients"`
	Attachments []EmailAttachment `json:"attachments,omitempty"`
	Status      string            `json:"status"` // pending, sent, failed
	CreatedAt   time.Time         `json:"created_at"`
	SentAt      *time.Time        `json:"sent_at,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// NotificationLog for audit trail (stored in ClickHouse)
type NotificationLog struct {
	ID           string    `json:"id" ch:"id"`
	Type         string    `json:"type" ch:"type"`
	Subject      string    `json:"subject" ch:"subject"`
	Recipients   []string  `json:"recipients" ch:"recipients"`
	Status       string    `json:"status" ch:"status"`
	TriggerEvent string    `json:"trigger_event" ch:"trigger_event"`
	CreatedAt    time.Time `json:"created_at" ch:"created_at"`
	SentAt       time.Time `json:"sent_at" ch:"sent_at"`
	Error        string    `json:"error" ch:"error"`
}

// ReportData holds data for scheduled reports
// v3.57.101: Enhanced with more fields for detailed admin reports
type ReportData struct {
	Period         string            `json:"period"` // daily, weekly, monthly
	StartDate      time.Time         `json:"start_date"`
	EndDate        time.Time         `json:"end_date"`
	TotalEvents    int               `json:"total_events"`
	BlockedEvents  int               `json:"blocked_events"`
	CriticalEvents int               `json:"critical_events"`
	HighEvents     int               `json:"high_events"`
	MediumEvents   int               `json:"medium_events"`
	LowEvents      int               `json:"low_events"`
	NewBans        int               `json:"new_bans"`
	UniqueIPs      int               `json:"unique_ips"`
	ActiveBans     int               `json:"active_bans"`
	TopAttackers   []TopAttacker     `json:"top_attackers"`
	TopTargets     []TopTarget       `json:"top_targets"`
	TopCountries   []CountryStats    `json:"top_countries"`
	TopAttackTypes []AttackTypeStats `json:"top_attack_types"`
	PeakHour       string            `json:"peak_hour"`
	CriticalAlerts []CriticalAlert   `json:"critical_alerts"`
}

// CountryStats holds country-level statistics for reports
type CountryStats struct {
	Country          string `json:"country"`
	Count            int    `json:"count"`
	Percentage       int    `json:"percentage"`
	PercentFormatted string `json:"percent_formatted"`
}

// AttackTypeStats holds attack type statistics for reports
type AttackTypeStats struct {
	Type             string `json:"type"`
	Count            int    `json:"count"`
	Percentage       int    `json:"percentage"`
	PercentFormatted string `json:"percent_formatted"`
}

// AlertData holds data for real-time alerts
type AlertData struct {
	AlertType   string    `json:"alert_type"` // waf_detection, waf_blocked, new_ban, critical
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	Country     string    `json:"country"`
	Target      string    `json:"target"`
	ThreatScore int       `json:"threat_score"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	Details     string    `json:"details"`
	Severity    string    `json:"severity"`
}
