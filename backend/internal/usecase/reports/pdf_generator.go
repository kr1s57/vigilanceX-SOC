package reports

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/go-pdf/fpdf"
)

// PDFGenerator generates PDF reports
type PDFGenerator struct{}

// NewPDFGenerator creates a new PDF generator
func NewPDFGenerator() *PDFGenerator {
	return &PDFGenerator{}
}

// Color definitions
var (
	colorPrimary = []int{37, 99, 235}   // Blue
	colorDanger  = []int{239, 68, 68}   // Red
	colorWarning = []int{245, 158, 11}  // Amber
	colorSuccess = []int{34, 197, 94}   // Green
	colorMuted   = []int{107, 114, 128} // Gray
	colorDark    = []int{31, 41, 55}    // Dark gray
	colorLight   = []int{243, 244, 246} // Light gray
	colorWhite   = []int{255, 255, 255}
)

// Generate creates a PDF report from the report data
func (g *PDFGenerator) Generate(data *ReportData) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 15)

	// Add cover page
	g.addCoverPage(pdf, data)

	// Add executive summary
	g.addExecutiveSummary(pdf, data)

	// Add event statistics
	if data.EventStats != nil {
		g.addEventStatistics(pdf, data)
	}

	// Add top attackers
	if data.EventStats != nil && len(data.EventStats.TopAttackers) > 0 {
		g.addTopAttackers(pdf, data)
	}

	// Add WAF/ModSec section
	if data.ModSecStats != nil {
		g.addModSecSection(pdf, data)
	}

	// Add VPN section
	if data.VPNStats != nil {
		g.addVPNSection(pdf, data)
	}

	// Add Threat Intelligence section
	if data.ThreatStats != nil {
		g.addThreatSection(pdf, data)
	}

	// Add Ban Management section
	if data.BanStats != nil {
		g.addBanSection(pdf, data)
	}

	// Generate output
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	return buf.Bytes(), nil
}

// addCoverPage adds the cover page
func (g *PDFGenerator) addCoverPage(pdf *fpdf.Fpdf, data *ReportData) {
	pdf.AddPage()

	// Background header
	pdf.SetFillColor(colorPrimary[0], colorPrimary[1], colorPrimary[2])
	pdf.Rect(0, 0, 210, 100, "F")

	// Title
	pdf.SetTextColor(colorWhite[0], colorWhite[1], colorWhite[2])
	pdf.SetFont("Helvetica", "B", 32)
	pdf.SetY(35)
	pdf.CellFormat(0, 12, "VIGILANCE X", "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 16)
	pdf.CellFormat(0, 8, "Security Operations Report", "", 1, "C", false, 0, "")

	// Report period
	pdf.SetY(70)
	pdf.SetFont("Helvetica", "", 12)
	pdf.CellFormat(0, 6, data.Period, "", 1, "C", false, 0, "")

	// Report type badge
	pdf.SetY(82)
	pdf.SetFont("Helvetica", "B", 10)
	reportTypeLabel := fmt.Sprintf("%s Report", g.capitalizeFirst(data.ReportType))
	pdf.CellFormat(0, 6, reportTypeLabel, "", 1, "C", false, 0, "")

	// Reset colors
	pdf.SetTextColor(colorDark[0], colorDark[1], colorDark[2])

	// Generation info
	pdf.SetY(120)
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(colorMuted[0], colorMuted[1], colorMuted[2])
	pdf.CellFormat(0, 6, fmt.Sprintf("Generated: %s", data.GeneratedAt.Format("January 2, 2006 at 15:04 UTC")), "", 1, "C", false, 0, "")

	// Database info
	if data.DBStats != nil {
		pdf.SetY(140)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.SetTextColor(colorDark[0], colorDark[1], colorDark[2])
		pdf.CellFormat(0, 8, "Database Overview", "", 1, "C", false, 0, "")

		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(colorMuted[0], colorMuted[1], colorMuted[2])
		pdf.CellFormat(0, 6, fmt.Sprintf("Size: %s | Total Events: %s", data.DBStats.DatabaseSize, g.formatNumber(data.DBStats.TotalEvents)), "", 1, "C", false, 0, "")

		if !data.DBStats.DateRangeStart.IsZero() && !data.DBStats.DateRangeEnd.IsZero() {
			pdf.CellFormat(0, 6, fmt.Sprintf("Data Range: %s to %s",
				data.DBStats.DateRangeStart.Format("Jan 2, 2006"),
				data.DBStats.DateRangeEnd.Format("Jan 2, 2006")), "", 1, "C", false, 0, "")
		}
	}

	// Footer
	pdf.SetY(270)
	pdf.SetFont("Helvetica", "I", 8)
	pdf.SetTextColor(colorMuted[0], colorMuted[1], colorMuted[2])
	pdf.CellFormat(0, 4, "Confidential - For authorized personnel only", "", 1, "C", false, 0, "")
}

// addExecutiveSummary adds the executive summary page
func (g *PDFGenerator) addExecutiveSummary(pdf *fpdf.Fpdf, data *ReportData) {
	pdf.AddPage()
	g.addSectionHeader(pdf, "Executive Summary")

	if data.EventStats == nil {
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(colorMuted[0], colorMuted[1], colorMuted[2])
		pdf.CellFormat(0, 8, "No event data available for this period.", "", 1, "L", false, 0, "")
		return
	}

	stats := data.EventStats

	// Key metrics cards (2x2 grid)
	startY := pdf.GetY() + 5
	cardWidth := 85.0
	cardHeight := 25.0

	// Card 1: Total Events
	g.drawMetricCard(pdf, 15, startY, cardWidth, cardHeight, "Total Events", g.formatNumber(stats.TotalEvents), colorPrimary)

	// Card 2: Blocked Events
	g.drawMetricCard(pdf, 105, startY, cardWidth, cardHeight, "Blocked Events", fmt.Sprintf("%s (%.1f%%)", g.formatNumber(stats.BlockedEvents), stats.BlockRate), colorDanger)

	// Card 3: Unique IPs
	g.drawMetricCard(pdf, 15, startY+30, cardWidth, cardHeight, "Unique Source IPs", g.formatNumber(stats.UniqueIPs), colorWarning)

	// Card 4: Critical Alerts
	g.drawMetricCard(pdf, 105, startY+30, cardWidth, cardHeight, "Critical Alerts", g.formatNumber(stats.CriticalEvents), colorDanger)

	pdf.SetY(startY + 70)

	// Severity breakdown
	g.addSubHeader(pdf, "Events by Severity")

	severityData := []struct {
		Label string
		Value uint64
		Color []int
	}{
		{"Critical", stats.CriticalEvents, colorDanger},
		{"High", stats.HighEvents, []int{249, 115, 22}},
		{"Medium", stats.MediumEvents, colorWarning},
		{"Low", stats.LowEvents, colorPrimary},
	}

	// Draw horizontal bar chart
	maxVal := stats.TotalEvents
	if maxVal == 0 {
		maxVal = 1
	}
	barY := pdf.GetY() + 3
	for _, s := range severityData {
		g.drawHorizontalBar(pdf, 15, barY, 120, 8, s.Label, s.Value, maxVal, s.Color)
		barY += 12
	}

	pdf.SetY(barY + 10)

	// Events by type
	if len(stats.EventsByType) > 0 {
		g.addSubHeader(pdf, "Events by Log Type")

		// Sort by count
		type kv struct {
			Key   string
			Value uint64
		}
		var sorted []kv
		for k, v := range stats.EventsByType {
			sorted = append(sorted, kv{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Value > sorted[j].Value
		})

		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(colorDark[0], colorDark[1], colorDark[2])

		for i, item := range sorted {
			if i >= 6 {
				break
			}
			percentage := float64(item.Value) / float64(stats.TotalEvents) * 100
			pdf.CellFormat(60, 6, item.Key, "", 0, "L", false, 0, "")
			pdf.CellFormat(40, 6, g.formatNumber(item.Value), "", 0, "R", false, 0, "")
			pdf.CellFormat(30, 6, fmt.Sprintf("%.1f%%", percentage), "", 1, "R", false, 0, "")
		}
	}
}

// addEventStatistics adds detailed event statistics
func (g *PDFGenerator) addEventStatistics(pdf *fpdf.Fpdf, data *ReportData) {
	pdf.AddPage()
	g.addSectionHeader(pdf, "Event Statistics")

	if data.EventStats == nil {
		return
	}

	// Top targets table
	if len(data.EventStats.TopTargets) > 0 {
		g.addSubHeader(pdf, "Top Targeted Hosts")

		headers := []string{"Hostname", "Attacks", "Unique IPs"}
		widths := []float64{90, 40, 40}

		g.drawTableHeader(pdf, headers, widths)

		for i, target := range data.EventStats.TopTargets {
			if i >= 10 {
				break
			}
			values := []string{
				g.truncateString(target.Hostname, 40),
				g.formatNumber(target.AttackCount),
				g.formatNumber(target.UniqueIPs),
			}
			g.drawTableRow(pdf, values, widths, i%2 == 0)
		}
	}

	pdf.Ln(10)

	// Top rules table
	if len(data.EventStats.TopRules) > 0 {
		g.addSubHeader(pdf, "Top Triggered Rules")

		headers := []string{"Rule ID", "Message", "Count"}
		widths := []float64{30, 110, 30}

		g.drawTableHeader(pdf, headers, widths)

		for i, rule := range data.EventStats.TopRules {
			if i >= 10 {
				break
			}
			values := []string{
				rule.RuleID,
				g.truncateString(rule.RuleMsg, 50),
				g.formatNumber(rule.TriggerCount),
			}
			g.drawTableRow(pdf, values, widths, i%2 == 0)
		}
	}
}

// addTopAttackers adds the top attackers section
func (g *PDFGenerator) addTopAttackers(pdf *fpdf.Fpdf, data *ReportData) {
	pdf.AddPage()
	g.addSectionHeader(pdf, "Top Attackers")

	headers := []string{"IP Address", "Country", "Attacks", "Blocked", "Rules"}
	widths := []float64{45, 25, 35, 35, 30}

	g.drawTableHeader(pdf, headers, widths)

	for i, attacker := range data.EventStats.TopAttackers {
		if i >= 15 {
			break
		}
		blockRate := float64(0)
		if attacker.AttackCount > 0 {
			blockRate = float64(attacker.BlockedCount) / float64(attacker.AttackCount) * 100
		}
		values := []string{
			attacker.IP,
			attacker.Country,
			g.formatNumber(attacker.AttackCount),
			fmt.Sprintf("%s (%.0f%%)", g.formatNumber(attacker.BlockedCount), blockRate),
			g.formatNumber(attacker.UniqueRules),
		}
		g.drawTableRow(pdf, values, widths, i%2 == 0)
	}

	// Geographic distribution
	if len(data.EventStats.TopCountries) > 0 {
		pdf.Ln(15)
		g.addSubHeader(pdf, "Geographic Distribution")

		headers := []string{"Country", "Attack Count", "Unique IPs"}
		widths := []float64{60, 55, 55}

		g.drawTableHeader(pdf, headers, widths)

		for i, country := range data.EventStats.TopCountries {
			if i >= 10 {
				break
			}
			values := []string{
				country.Country,
				g.formatNumber(country.AttackCount),
				g.formatNumber(country.UniqueIPs),
			}
			g.drawTableRow(pdf, values, widths, i%2 == 0)
		}
	}
}

// addModSecSection adds the ModSecurity/WAF section
func (g *PDFGenerator) addModSecSection(pdf *fpdf.Fpdf, data *ReportData) {
	pdf.AddPage()
	g.addSectionHeader(pdf, "WAF / ModSecurity Analysis")

	stats := data.ModSecStats

	// Summary metrics
	startY := pdf.GetY() + 5
	g.drawMetricCard(pdf, 15, startY, 55, 22, "Total Detections", g.formatNumber(stats.TotalLogs), colorPrimary)
	g.drawMetricCard(pdf, 75, startY, 55, 22, "Blocked", g.formatNumber(stats.BlockingLogs), colorDanger)
	g.drawMetricCard(pdf, 135, startY, 55, 22, "Unique Rules", g.formatNumber(stats.UniqueRules), colorWarning)

	pdf.SetY(startY + 35)

	// Attack types
	if len(stats.TopAttackTypes) > 0 {
		g.addSubHeader(pdf, "Attack Types Distribution")

		maxCount := uint64(1)
		for _, at := range stats.TopAttackTypes {
			if at.Count > maxCount {
				maxCount = at.Count
			}
		}

		barY := pdf.GetY() + 3
		colors := [][]int{colorDanger, colorWarning, colorPrimary, colorSuccess, colorMuted}
		for i, at := range stats.TopAttackTypes {
			if i >= 8 {
				break
			}
			color := colors[i%len(colors)]
			g.drawHorizontalBar(pdf, 15, barY, 120, 7, at.Type, at.Count, maxCount, color)
			barY += 10
		}
		pdf.SetY(barY + 5)
	}

	// Top triggered rules
	if len(stats.TopTriggeredRules) > 0 {
		g.addSubHeader(pdf, "Most Triggered Rules")

		headers := []string{"Rule ID", "Message", "Triggers", "IPs"}
		widths := []float64{25, 95, 25, 25}

		g.drawTableHeader(pdf, headers, widths)

		for i, rule := range stats.TopTriggeredRules {
			if i >= 10 {
				break
			}
			values := []string{
				rule.RuleID,
				g.truncateString(rule.RuleMsg, 45),
				g.formatNumber(rule.TriggerCount),
				g.formatNumber(rule.UniqueIPs),
			}
			g.drawTableRow(pdf, values, widths, i%2 == 0)
		}
	}
}

// addVPNSection adds the VPN statistics section
func (g *PDFGenerator) addVPNSection(pdf *fpdf.Fpdf, data *ReportData) {
	pdf.AddPage()
	g.addSectionHeader(pdf, "VPN & Network Activity")

	stats := data.VPNStats

	// Summary cards
	startY := pdf.GetY() + 5
	g.drawMetricCard(pdf, 15, startY, 42, 22, "Total Events", g.formatNumber(stats.TotalEvents), colorPrimary)
	g.drawMetricCard(pdf, 60, startY, 42, 22, "Connections", g.formatNumber(stats.Connections), colorSuccess)
	g.drawMetricCard(pdf, 105, startY, 42, 22, "Disconnects", g.formatNumber(stats.Disconnections), colorWarning)
	g.drawMetricCard(pdf, 150, startY, 42, 22, "Auth Failures", g.formatNumber(stats.AuthFailures), colorDanger)

	pdf.SetY(startY + 35)

	// User summary
	g.addSubHeader(pdf, "User Activity Summary")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(colorDark[0], colorDark[1], colorDark[2])
	pdf.CellFormat(0, 8, fmt.Sprintf("Unique Users: %s", g.formatNumber(stats.UniqueUsers)), "", 1, "L", false, 0, "")

	if stats.AuthFailures > 0 {
		pdf.Ln(5)
		pdf.SetTextColor(colorDanger[0], colorDanger[1], colorDanger[2])
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(0, 8, fmt.Sprintf("Warning: %d authentication failures detected", stats.AuthFailures), "", 1, "L", false, 0, "")
	}
}

// addThreatSection adds the threat intelligence section
func (g *PDFGenerator) addThreatSection(pdf *fpdf.Fpdf, data *ReportData) {
	pdf.AddPage()
	g.addSectionHeader(pdf, "Threat Intelligence Summary")

	stats := data.ThreatStats

	// Summary cards
	startY := pdf.GetY() + 5
	g.drawMetricCard(pdf, 15, startY, 55, 22, "IPs Tracked", g.formatNumber(stats.TotalTracked), colorPrimary)
	g.drawMetricCard(pdf, 75, startY, 55, 22, "Critical Threats", g.formatNumber(stats.CriticalCount), colorDanger)
	g.drawMetricCard(pdf, 135, startY, 55, 22, "Tor Nodes", g.formatNumber(stats.TorExitNodes), colorWarning)

	pdf.SetY(startY + 35)

	// Threat level breakdown
	g.addSubHeader(pdf, "Threat Level Distribution")

	threatData := []struct {
		Label string
		Value uint64
		Color []int
	}{
		{"Critical", stats.CriticalCount, colorDanger},
		{"High", stats.HighCount, []int{249, 115, 22}},
		{"Medium", stats.MediumCount, colorWarning},
		{"Low", stats.LowCount, colorSuccess},
	}

	total := stats.TotalTracked
	if total == 0 {
		total = 1
	}

	barY := pdf.GetY() + 3
	for _, t := range threatData {
		g.drawHorizontalBar(pdf, 15, barY, 120, 8, t.Label, t.Value, total, t.Color)
		barY += 12
	}
}

// addBanSection adds the ban management section
func (g *PDFGenerator) addBanSection(pdf *fpdf.Fpdf, data *ReportData) {
	pdf.AddPage()
	g.addSectionHeader(pdf, "Ban Management Activity")

	stats := data.BanStats

	// Summary cards
	startY := pdf.GetY() + 5
	g.drawMetricCard(pdf, 15, startY, 42, 22, "Active Bans", g.formatNumber(stats.ActiveBans), colorDanger)
	g.drawMetricCard(pdf, 60, startY, 42, 22, "Permanent", g.formatNumber(stats.PermanentBans), colorDark)
	g.drawMetricCard(pdf, 105, startY, 42, 22, "New Bans", g.formatNumber(stats.NewBans), colorWarning)
	g.drawMetricCard(pdf, 150, startY, 42, 22, "Unbans", g.formatNumber(stats.Unbans), colorSuccess)

	pdf.SetY(startY + 35)

	// Summary text
	g.addSubHeader(pdf, "Period Summary")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(colorDark[0], colorDark[1], colorDark[2])

	totalActive := stats.ActiveBans + stats.PermanentBans
	pdf.MultiCell(0, 6, fmt.Sprintf(
		"During this period, %d new IP addresses were banned and %d were unbanned. "+
			"Currently, there are %d active bans (%d temporary, %d permanent) and %d expired bans in the database.",
		stats.NewBans, stats.Unbans, totalActive, stats.ActiveBans, stats.PermanentBans, stats.ExpiredBans,
	), "", "L", false)
}

// Helper functions

func (g *PDFGenerator) addSectionHeader(pdf *fpdf.Fpdf, title string) {
	pdf.SetFont("Helvetica", "B", 16)
	pdf.SetTextColor(colorDark[0], colorDark[1], colorDark[2])
	pdf.CellFormat(0, 10, title, "", 1, "L", false, 0, "")
	pdf.SetDrawColor(colorPrimary[0], colorPrimary[1], colorPrimary[2])
	pdf.SetLineWidth(0.5)
	pdf.Line(15, pdf.GetY(), 195, pdf.GetY())
	pdf.Ln(5)
}

func (g *PDFGenerator) addSubHeader(pdf *fpdf.Fpdf, title string) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(colorDark[0], colorDark[1], colorDark[2])
	pdf.CellFormat(0, 8, title, "", 1, "L", false, 0, "")
	pdf.Ln(2)
}

func (g *PDFGenerator) drawMetricCard(pdf *fpdf.Fpdf, x, y, w, h float64, label string, value string, color []int) {
	// Card background
	pdf.SetFillColor(colorLight[0], colorLight[1], colorLight[2])
	pdf.RoundedRect(x, y, w, h, 2, "1234", "F")

	// Color accent
	pdf.SetFillColor(color[0], color[1], color[2])
	pdf.Rect(x, y, 3, h, "F")

	// Label
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(colorMuted[0], colorMuted[1], colorMuted[2])
	pdf.SetXY(x+6, y+3)
	pdf.CellFormat(w-8, 4, label, "", 0, "L", false, 0, "")

	// Value
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(colorDark[0], colorDark[1], colorDark[2])
	pdf.SetXY(x+6, y+10)
	pdf.CellFormat(w-8, 8, value, "", 0, "L", false, 0, "")
}

func (g *PDFGenerator) drawHorizontalBar(pdf *fpdf.Fpdf, x, y, maxWidth, height float64, label string, value, maxValue uint64, color []int) {
	// Label
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(colorDark[0], colorDark[1], colorDark[2])
	pdf.SetXY(x, y)
	pdf.CellFormat(50, height, label, "", 0, "L", false, 0, "")

	// Bar background
	barX := x + 52
	barWidth := maxWidth - 80
	pdf.SetFillColor(colorLight[0], colorLight[1], colorLight[2])
	pdf.Rect(barX, y+1, barWidth, height-2, "F")

	// Bar fill
	if maxValue > 0 {
		fillWidth := float64(value) / float64(maxValue) * barWidth
		pdf.SetFillColor(color[0], color[1], color[2])
		pdf.Rect(barX, y+1, fillWidth, height-2, "F")
	}

	// Value
	pdf.SetXY(barX+barWidth+3, y)
	pdf.CellFormat(25, height, g.formatNumber(value), "", 0, "R", false, 0, "")
}

func (g *PDFGenerator) drawTableHeader(pdf *fpdf.Fpdf, headers []string, widths []float64) {
	pdf.SetFillColor(colorDark[0], colorDark[1], colorDark[2])
	pdf.SetTextColor(colorWhite[0], colorWhite[1], colorWhite[2])
	pdf.SetFont("Helvetica", "B", 9)

	for i, header := range headers {
		pdf.CellFormat(widths[i], 7, header, "", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)
}

func (g *PDFGenerator) drawTableRow(pdf *fpdf.Fpdf, values []string, widths []float64, alternate bool) {
	if alternate {
		pdf.SetFillColor(colorLight[0], colorLight[1], colorLight[2])
	} else {
		pdf.SetFillColor(colorWhite[0], colorWhite[1], colorWhite[2])
	}
	pdf.SetTextColor(colorDark[0], colorDark[1], colorDark[2])
	pdf.SetFont("Helvetica", "", 8)

	for i, value := range values {
		pdf.CellFormat(widths[i], 6, value, "", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)
}

func (g *PDFGenerator) formatNumber(n uint64) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func (g *PDFGenerator) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func (g *PDFGenerator) capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return string(s[0]-32) + s[1:]
}
