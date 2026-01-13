package entity

import "time"

// RetentionSettings holds log retention configuration
type RetentionSettings struct {
	// Retention periods in days
	EventsRetentionDays          int `json:"events_retention_days" ch:"events_retention_days"`
	ModsecLogsRetentionDays      int `json:"modsec_logs_retention_days" ch:"modsec_logs_retention_days"`
	FirewallEventsRetentionDays  int `json:"firewall_events_retention_days" ch:"firewall_events_retention_days"`
	VpnEventsRetentionDays       int `json:"vpn_events_retention_days" ch:"vpn_events_retention_days"`
	HeartbeatEventsRetentionDays int `json:"heartbeat_events_retention_days" ch:"heartbeat_events_retention_days"`
	AtpEventsRetentionDays       int `json:"atp_events_retention_days" ch:"atp_events_retention_days"`
	AntivirusEventsRetentionDays int `json:"antivirus_events_retention_days" ch:"antivirus_events_retention_days"`
	BanHistoryRetentionDays      int `json:"ban_history_retention_days" ch:"ban_history_retention_days"`
	AuditLogRetentionDays        int `json:"audit_log_retention_days" ch:"audit_log_retention_days"`

	// Global toggle
	RetentionEnabled bool `json:"retention_enabled" ch:"retention_enabled"`

	// Cleanup schedule
	LastCleanup          time.Time `json:"last_cleanup" ch:"last_cleanup"`
	CleanupIntervalHours int       `json:"cleanup_interval_hours" ch:"cleanup_interval_hours"`

	// Metadata
	UpdatedAt time.Time `json:"updated_at" ch:"updated_at"`
	UpdatedBy string    `json:"updated_by" ch:"updated_by"`
}

// DefaultRetentionSettings returns sensible defaults (30 days for most tables)
func DefaultRetentionSettings() *RetentionSettings {
	return &RetentionSettings{
		EventsRetentionDays:          30,
		ModsecLogsRetentionDays:      30,
		FirewallEventsRetentionDays:  30,
		VpnEventsRetentionDays:       30,
		HeartbeatEventsRetentionDays: 30,
		AtpEventsRetentionDays:       90,
		AntivirusEventsRetentionDays: 90,
		BanHistoryRetentionDays:      365,
		AuditLogRetentionDays:        365,
		RetentionEnabled:             true,
		CleanupIntervalHours:         6,
		UpdatedAt:                    time.Now(),
		UpdatedBy:                    "system",
	}
}

// RetentionStats holds cleanup statistics
type RetentionStats struct {
	TableName     string    `json:"table_name"`
	RowsDeleted   int64     `json:"rows_deleted"`
	RowsBefore    int64     `json:"rows_before"`
	RowsAfter     int64     `json:"rows_after"`
	Duration      float64   `json:"duration_ms"`
	CleanupTime   time.Time `json:"cleanup_time"`
	RetentionDays int       `json:"retention_days"`
}

// CleanupResult holds the result of a cleanup operation
type CleanupResult struct {
	Success      bool             `json:"success"`
	StartTime    time.Time        `json:"start_time"`
	EndTime      time.Time        `json:"end_time"`
	TotalDeleted int64            `json:"total_deleted"`
	TableStats   []RetentionStats `json:"table_stats"`
	Error        string           `json:"error,omitempty"`
}

// StorageStats holds disk usage information
type StorageStats struct {
	TotalBytes     int64            `json:"total_bytes"`
	UsedBytes      int64            `json:"used_bytes"`
	AvailableBytes int64            `json:"available_bytes"`
	UsedPercent    float64          `json:"used_percent"`
	TablesSize     map[string]int64 `json:"tables_size"`
}
