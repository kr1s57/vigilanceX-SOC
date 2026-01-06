package reports

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
)

// ReportConfig defines the configuration for generating a report
type ReportConfig struct {
	Type      string    `json:"type"`       // "daily", "weekly", "monthly", "custom"
	Format    string    `json:"format"`     // "pdf", "xml"
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Modules   []string  `json:"modules"`    // ["waf", "vpn", "threats", "bans"]
}

// ReportData holds all data needed for a report
type ReportData struct {
	// Metadata
	GeneratedAt time.Time `json:"generated_at"`
	ReportType  string    `json:"report_type"`
	Period      string    `json:"period"`
	StartDate   time.Time `json:"start_date"`
	EndDate     time.Time `json:"end_date"`

	// Database stats
	DBStats *clickhouse.DBStats `json:"db_stats,omitempty"`

	// Event statistics
	EventStats *clickhouse.ReportStats `json:"event_stats,omitempty"`

	// Module-specific stats
	BanStats    *clickhouse.BanStats    `json:"ban_stats,omitempty"`
	ThreatStats *clickhouse.ThreatStats `json:"threat_stats,omitempty"`
	ModSecStats *clickhouse.ModSecStats `json:"modsec_stats,omitempty"`
	VPNStats    *clickhouse.VPNStats    `json:"vpn_stats,omitempty"`
}

// Service handles report generation
type Service struct {
	statsRepo    *clickhouse.StatsRepository
	pdfGenerator *PDFGenerator
	xmlGenerator *XMLGenerator
	logger       *slog.Logger
}

// NewService creates a new reports service
func NewService(statsRepo *clickhouse.StatsRepository, logger *slog.Logger) *Service {
	return &Service{
		statsRepo:    statsRepo,
		pdfGenerator: NewPDFGenerator(),
		xmlGenerator: NewXMLGenerator(),
		logger:       logger,
	}
}

// GetDBStats returns current database statistics
func (s *Service) GetDBStats(ctx context.Context) (*clickhouse.DBStats, error) {
	return s.statsRepo.GetDBStats(ctx)
}

// GenerateReport generates a report based on the configuration
func (s *Service) GenerateReport(ctx context.Context, config ReportConfig) ([]byte, string, error) {
	// Calculate date range based on report type
	startDate, endDate := s.calculateDateRange(config)

	s.logger.Info("Generating report",
		"type", config.Type,
		"format", config.Format,
		"start", startDate,
		"end", endDate,
		"modules", config.Modules,
	)

	// Build report data
	reportData, err := s.buildReportData(ctx, startDate, endDate, config.Modules)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build report data: %w", err)
	}

	reportData.ReportType = config.Type
	reportData.Period = s.formatPeriod(startDate, endDate)

	// Generate output based on format
	var data []byte
	var filename string

	switch config.Format {
	case "pdf":
		data, err = s.pdfGenerator.Generate(reportData)
		filename = fmt.Sprintf("vigilancex-report-%s-%s.pdf", config.Type, time.Now().Format("2006-01-02"))
	case "xml":
		data, err = s.xmlGenerator.Generate(reportData)
		filename = fmt.Sprintf("vigilancex-report-%s-%s.xml", config.Type, time.Now().Format("2006-01-02"))
	default:
		return nil, "", fmt.Errorf("unsupported format: %s", config.Format)
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to generate %s: %w", config.Format, err)
	}

	s.logger.Info("Report generated successfully",
		"format", config.Format,
		"size", len(data),
		"filename", filename,
	)

	return data, filename, nil
}

// calculateDateRange calculates the date range based on report type
func (s *Service) calculateDateRange(config ReportConfig) (time.Time, time.Time) {
	now := time.Now().UTC()

	switch config.Type {
	case "daily":
		// Yesterday 00:00:00 to 23:59:59
		startOfYesterday := time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, time.UTC)
		endOfYesterday := time.Date(now.Year(), now.Month(), now.Day()-1, 23, 59, 59, 999999999, time.UTC)
		return startOfYesterday, endOfYesterday

	case "weekly":
		// Last 7 days
		startDate := now.AddDate(0, 0, -7)
		startDate = time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)
		endDate := time.Date(now.Year(), now.Month(), now.Day()-1, 23, 59, 59, 999999999, time.UTC)
		return startDate, endDate

	case "monthly":
		// Last 30 days
		startDate := now.AddDate(0, 0, -30)
		startDate = time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)
		endDate := time.Date(now.Year(), now.Month(), now.Day()-1, 23, 59, 59, 999999999, time.UTC)
		return startDate, endDate

	case "custom":
		return config.StartDate, config.EndDate

	default:
		// Default to last 24 hours
		return now.Add(-24 * time.Hour), now
	}
}

// buildReportData builds the report data from various sources
func (s *Service) buildReportData(ctx context.Context, startDate, endDate time.Time, modules []string) (*ReportData, error) {
	data := &ReportData{
		GeneratedAt: time.Now().UTC(),
		StartDate:   startDate,
		EndDate:     endDate,
	}

	// Always get DB stats
	dbStats, err := s.statsRepo.GetDBStats(ctx)
	if err != nil {
		s.logger.Warn("Failed to get DB stats", "error", err)
	} else {
		data.DBStats = dbStats
	}

	// Always get event stats
	eventStats, err := s.statsRepo.GetReportStats(ctx, startDate, endDate)
	if err != nil {
		s.logger.Warn("Failed to get event stats", "error", err)
	} else {
		data.EventStats = eventStats
	}

	// Get module-specific stats based on selection
	moduleSet := make(map[string]bool)
	for _, m := range modules {
		moduleSet[m] = true
	}

	// If no modules specified, include all
	if len(modules) == 0 {
		moduleSet["waf"] = true
		moduleSet["vpn"] = true
		moduleSet["threats"] = true
		moduleSet["bans"] = true
	}

	if moduleSet["waf"] {
		modSecStats, err := s.statsRepo.GetModSecStats(ctx, startDate, endDate)
		if err != nil {
			s.logger.Warn("Failed to get ModSec stats", "error", err)
		} else {
			data.ModSecStats = modSecStats
		}
	}

	if moduleSet["vpn"] {
		vpnStats, err := s.statsRepo.GetVPNStats(ctx, startDate, endDate)
		if err != nil {
			s.logger.Warn("Failed to get VPN stats", "error", err)
		} else {
			data.VPNStats = vpnStats
		}
	}

	if moduleSet["threats"] {
		threatStats, err := s.statsRepo.GetThreatStats(ctx)
		if err != nil {
			s.logger.Warn("Failed to get threat stats", "error", err)
		} else {
			data.ThreatStats = threatStats
		}
	}

	if moduleSet["bans"] {
		banStats, err := s.statsRepo.GetBanStats(ctx, startDate, endDate)
		if err != nil {
			s.logger.Warn("Failed to get ban stats", "error", err)
		} else {
			data.BanStats = banStats
		}
	}

	return data, nil
}

// formatPeriod formats the date range for display
func (s *Service) formatPeriod(startDate, endDate time.Time) string {
	if startDate.Format("2006-01-02") == endDate.Format("2006-01-02") {
		return startDate.Format("January 2, 2006")
	}
	return fmt.Sprintf("%s - %s", startDate.Format("Jan 2, 2006"), endDate.Format("Jan 2, 2006"))
}

// GetPreviewData returns report data without generating the final file
func (s *Service) GetPreviewData(ctx context.Context, config ReportConfig) (*ReportData, error) {
	startDate, endDate := s.calculateDateRange(config)
	return s.buildReportData(ctx, startDate, endDate, config.Modules)
}
