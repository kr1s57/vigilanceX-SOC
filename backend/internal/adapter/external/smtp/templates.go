package smtp

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// Template names
const (
	TemplateDailyReport   = "daily_report"
	TemplateWeeklyReport  = "weekly_report"
	TemplateMonthlyReport = "monthly_report"
	TemplateWAFAlert      = "waf_alert"
	TemplateBanAlert      = "ban_alert"
	TemplateCriticalAlert = "critical_alert"
	TemplateTestEmail     = "test_email"
)

// RenderDailyReport renders the daily report email
func RenderDailyReport(data *entity.ReportData) (subject, textBody, htmlBody string) {
	subject = fmt.Sprintf("[VIGILANCE X] Daily Security Report - %s", data.EndDate.Format("2006-01-02"))

	textBody = fmt.Sprintf(`VIGILANCE X - Daily Security Report
Date: %s

SECURITY OVERVIEW
-----------------
Total Events: %d
Blocked Events: %d
Critical Events: %d
High Severity: %d
New IPs Banned: %d
Unique Source IPs: %d

TOP ATTACKERS
-------------
`, data.EndDate.Format("2006-01-02"),
		data.TotalEvents, data.BlockedEvents, data.CriticalEvents,
		data.HighEvents, data.NewBans, data.UniqueIPs)

	for i, attacker := range data.TopAttackers {
		if i >= 10 {
			break
		}
		textBody += fmt.Sprintf("%d. %s (%s) - %d events, Score: %d\n",
			i+1, attacker.IP, attacker.Country, attacker.AttackCount, attacker.ThreatScore)
	}

	htmlBody = renderHTMLReport(data, "Daily")
	return
}

// RenderWeeklyReport renders the weekly report email
func RenderWeeklyReport(data *entity.ReportData) (subject, textBody, htmlBody string) {
	subject = fmt.Sprintf("[VIGILANCE X] Weekly Security Report - Week of %s", data.StartDate.Format("2006-01-02"))

	textBody = fmt.Sprintf(`VIGILANCE X - Weekly Security Report
Period: %s to %s

SECURITY OVERVIEW
-----------------
Total Events: %d
Blocked Events: %d
Critical Events: %d
High Severity: %d
New IPs Banned: %d
Unique Source IPs: %d
`,
		data.StartDate.Format("2006-01-02"), data.EndDate.Format("2006-01-02"),
		data.TotalEvents, data.BlockedEvents, data.CriticalEvents,
		data.HighEvents, data.NewBans, data.UniqueIPs)

	htmlBody = renderHTMLReport(data, "Weekly")
	return
}

// RenderMonthlyReport renders the monthly report email
func RenderMonthlyReport(data *entity.ReportData) (subject, textBody, htmlBody string) {
	subject = fmt.Sprintf("[VIGILANCE X] Monthly Security Report - %s", data.StartDate.Format("January 2006"))

	textBody = fmt.Sprintf(`VIGILANCE X - Monthly Security Report
Period: %s to %s

SECURITY OVERVIEW
-----------------
Total Events: %d
Blocked Events: %d
Critical Events: %d
High Severity: %d
New IPs Banned: %d
Unique Source IPs: %d
`,
		data.StartDate.Format("2006-01-02"), data.EndDate.Format("2006-01-02"),
		data.TotalEvents, data.BlockedEvents, data.CriticalEvents,
		data.HighEvents, data.NewBans, data.UniqueIPs)

	htmlBody = renderHTMLReport(data, "Monthly")
	return
}

// RenderWAFAlert renders a WAF detection alert email
func RenderWAFAlert(data *entity.AlertData) (subject, textBody, htmlBody string) {
	alertType := "WAF Detection"
	if data.AlertType == "waf_blocked" {
		alertType = "WAF BLOCKED"
	}

	subject = fmt.Sprintf("[VIGILANCE X] %s: %s from %s", alertType, data.RuleName, data.SourceIP)

	textBody = fmt.Sprintf(`VIGILANCE X - %s Alert

Time: %s
Source IP: %s
Country: %s
Target: %s
Rule: %s (%s)
Severity: %s
Threat Score: %d/100

Details:
%s
`,
		alertType,
		data.Timestamp.Format("2006-01-02 15:04:05"),
		data.SourceIP, data.Country, data.Target,
		data.RuleID, data.RuleName,
		data.Severity, data.ThreatScore,
		data.Details)

	htmlBody = renderHTMLAlert(data, alertType, "#f97316") // orange
	return
}

// RenderBanAlert renders a new ban alert email
func RenderBanAlert(data *entity.AlertData) (subject, textBody, htmlBody string) {
	subject = fmt.Sprintf("[VIGILANCE X] New IP Banned: %s (%s)", data.SourceIP, data.Country)

	textBody = fmt.Sprintf(`VIGILANCE X - New IP Banned

Time: %s
Banned IP: %s
Country: %s
Threat Score: %d/100
Reason: %s

This IP has been automatically banned based on threat intelligence and behavior analysis.
`,
		data.Timestamp.Format("2006-01-02 15:04:05"),
		data.SourceIP, data.Country,
		data.ThreatScore, data.Details)

	htmlBody = renderHTMLAlert(data, "IP Banned", "#dc2626") // red
	return
}

// RenderCriticalAlert renders a critical severity alert email
func RenderCriticalAlert(data *entity.AlertData) (subject, textBody, htmlBody string) {
	subject = fmt.Sprintf("[VIGILANCE X] CRITICAL ALERT: %s from %s", data.RuleName, data.SourceIP)

	textBody = fmt.Sprintf(`VIGILANCE X - CRITICAL SECURITY ALERT

Time: %s
Source IP: %s
Country: %s
Target: %s
Event Type: %s
Severity: CRITICAL
Threat Score: %d/100

Details:
%s

IMMEDIATE ACTION MAY BE REQUIRED
`,
		data.Timestamp.Format("2006-01-02 15:04:05"),
		data.SourceIP, data.Country, data.Target,
		data.RuleName, data.ThreatScore, data.Details)

	htmlBody = renderHTMLAlert(data, "CRITICAL ALERT", "#dc2626") // red
	return
}

// RenderTestEmail renders a test email
func RenderTestEmail() (subject, textBody, htmlBody string) {
	subject = "[VIGILANCE X] Test Email - Configuration Successful"

	textBody = fmt.Sprintf(`VIGILANCE X - Test Email

This is a test email to verify your SMTP configuration.

If you received this email, your SMTP settings are correctly configured.

Sent at: %s
`, time.Now().Format("2006-01-02 15:04:05"))

	htmlBody = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>VIGILANCE X Test Email</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
  <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; text-align: center;">
    <h1 style="margin: 0; font-size: 28px;">VIGILANCE X</h1>
    <p style="margin: 10px 0 0 0; opacity: 0.9;">Security Operations Center</p>
  </div>

  <div style="padding: 30px; background: #f9fafb;">
    <div style="background: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
      <div style="text-align: center; margin-bottom: 20px;">
        <div style="width: 60px; height: 60px; background: #10b981; border-radius: 50%; margin: 0 auto; display: flex; align-items: center; justify-content: center;">
          <span style="color: white; font-size: 30px;">✓</span>
        </div>
      </div>

      <h2 style="text-align: center; color: #10b981; margin: 0 0 20px 0;">Configuration Successful!</h2>

      <p style="text-align: center; color: #6b7280;">
        This is a test email to verify your SMTP configuration.<br>
        If you received this email, your settings are correctly configured.
      </p>

      <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center; color: #9ca3af; font-size: 12px;">
        Sent at: ` + time.Now().Format("2006-01-02 15:04:05") + `
      </div>
    </div>
  </div>

  <div style="padding: 20px; text-align: center; color: #9ca3af; font-size: 12px;">
    VIGILANCE X Security Operations Center
  </div>
</body>
</html>`

	return
}

// renderHTMLReport generates an HTML report email
// v3.57.101: Enhanced report with more detailed information for admins
func renderHTMLReport(data *entity.ReportData, reportType string) string {
	// Calculate block rate
	blockRate := float64(0)
	if data.TotalEvents > 0 {
		blockRate = float64(data.BlockedEvents) / float64(data.TotalEvents) * 100
	}

	tmpl := `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>VIGILANCE X {{.ReportType}} Report</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #1f2937; margin: 0; padding: 0; background: #f3f4f6; }
    .container { max-width: 800px; margin: 0 auto; }
    .header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%); color: white; padding: 40px 30px; }
    .header h1 { margin: 0; font-size: 32px; font-weight: 700; letter-spacing: -0.5px; }
    .header .subtitle { margin: 8px 0 0 0; opacity: 0.9; font-size: 18px; }
    .header .period { margin: 4px 0 0 0; font-size: 14px; opacity: 0.7; }
    .content { padding: 30px; }
    .section { margin-bottom: 30px; }
    .section-title { color: #0f172a; margin: 0 0 16px 0; font-size: 16px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; display: flex; align-items: center; gap: 8px; }
    .section-title::before { content: ''; display: block; width: 4px; height: 20px; background: #3b82f6; border-radius: 2px; }
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
    .stat-card { background: white; border-radius: 12px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #e5e7eb; }
    .stat-value { font-size: 32px; font-weight: 700; line-height: 1.2; }
    .stat-label { font-size: 12px; color: #6b7280; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.3px; }
    .stat-sublabel { font-size: 11px; color: #9ca3af; margin-top: 2px; }
    .severity-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .severity-card { background: white; border-radius: 8px; padding: 16px; text-align: center; border: 1px solid #e5e7eb; }
    .severity-card.critical { border-left: 4px solid #dc2626; }
    .severity-card.high { border-left: 4px solid #f97316; }
    .severity-card.medium { border-left: 4px solid #eab308; }
    .severity-card.low { border-left: 4px solid #3b82f6; }
    .severity-value { font-size: 24px; font-weight: 700; }
    .severity-label { font-size: 11px; color: #6b7280; text-transform: uppercase; }
    .table-container { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #e5e7eb; }
    table { width: 100%; border-collapse: collapse; }
    th { background: #f8fafc; padding: 14px 16px; text-align: left; font-size: 11px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #e5e7eb; }
    td { padding: 14px 16px; border-bottom: 1px solid #f1f5f9; font-size: 14px; }
    tr:last-child td { border-bottom: none; }
    tr:hover { background: #f8fafc; }
    .ip-cell { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 13px; font-weight: 500; }
    .score-badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }
    .score-high { background: #fef2f2; color: #dc2626; }
    .score-medium { background: #fef9c3; color: #ca8a04; }
    .score-low { background: #f0fdf4; color: #16a34a; }
    .rank { width: 30px; color: #9ca3af; font-weight: 600; }
    .bar-container { height: 6px; background: #e5e7eb; border-radius: 3px; overflow: hidden; margin-top: 4px; }
    .bar { height: 100%; border-radius: 3px; transition: width 0.3s; }
    .bar-red { background: linear-gradient(90deg, #f87171, #dc2626); }
    .bar-orange { background: linear-gradient(90deg, #fb923c, #f97316); }
    .bar-blue { background: linear-gradient(90deg, #60a5fa, #3b82f6); }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .footer { padding: 24px 30px; text-align: center; color: #9ca3af; font-size: 12px; background: #f8fafc; border-top: 1px solid #e5e7eb; }
    .footer-brand { font-weight: 600; color: #64748b; }
    .metric-row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #f1f5f9; }
    .metric-row:last-child { border-bottom: none; }
    .metric-label { color: #6b7280; font-size: 13px; }
    .metric-value { font-weight: 600; font-size: 14px; }
    .highlight-box { background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); border: 1px solid #f59e0b; border-radius: 8px; padding: 16px; margin-bottom: 20px; }
    .highlight-box.danger { background: linear-gradient(135deg, #fef2f2 0%, #fecaca 100%); border-color: #dc2626; }
    .highlight-title { font-weight: 600; color: #92400e; font-size: 14px; margin-bottom: 4px; }
    .highlight-box.danger .highlight-title { color: #991b1b; }
    .highlight-text { color: #78350f; font-size: 13px; }
    .highlight-box.danger .highlight-text { color: #7f1d1d; }
    @media (max-width: 600px) {
      .stats-grid, .severity-grid { grid-template-columns: repeat(2, 1fr); }
      .two-col { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>VIGILANCE X</h1>
      <p class="subtitle">{{.ReportType}} Security Report</p>
      <p class="period">📅 {{.Period}}</p>
    </div>

    <div class="content">
      {{if gt .CriticalEvents 10}}
      <div class="highlight-box danger">
        <div class="highlight-title">⚠️ High Critical Activity Detected</div>
        <div class="highlight-text">{{.CriticalEvents}} critical events were detected during this period. Immediate review recommended.</div>
      </div>
      {{end}}

      <!-- Main Stats -->
      <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-value" style="color: #0f172a;">{{.TotalEventsFormatted}}</div>
            <div class="stat-label">Total Events</div>
            <div class="stat-sublabel">All security events</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" style="color: #10b981;">{{.BlockedEventsFormatted}}</div>
            <div class="stat-label">Blocked</div>
            <div class="stat-sublabel">{{.BlockRate}}% block rate</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" style="color: #8b5cf6;">{{.UniqueIPsFormatted}}</div>
            <div class="stat-label">Unique IPs</div>
            <div class="stat-sublabel">Source addresses</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" style="color: #f97316;">{{.NewBansFormatted}}</div>
            <div class="stat-label">New Bans</div>
            <div class="stat-sublabel">Auto-blocked IPs</div>
          </div>
        </div>
      </div>

      <!-- Severity Breakdown -->
      <div class="section">
        <h2 class="section-title">Severity Distribution</h2>
        <div class="severity-grid">
          <div class="severity-card critical">
            <div class="severity-value" style="color: #dc2626;">{{.CriticalEventsFormatted}}</div>
            <div class="severity-label">Critical</div>
          </div>
          <div class="severity-card high">
            <div class="severity-value" style="color: #f97316;">{{.HighEventsFormatted}}</div>
            <div class="severity-label">High</div>
          </div>
          <div class="severity-card medium">
            <div class="severity-value" style="color: #eab308;">{{.MediumEventsFormatted}}</div>
            <div class="severity-label">Medium</div>
          </div>
          <div class="severity-card low">
            <div class="severity-value" style="color: #3b82f6;">{{.LowEventsFormatted}}</div>
            <div class="severity-label">Low</div>
          </div>
        </div>
      </div>

      {{if .TopAttackers}}
      <!-- Top Attackers -->
      <div class="section">
        <h2 class="section-title">Top Attacking IPs</h2>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th class="rank">#</th>
                <th>IP Address</th>
                <th>Country</th>
                <th style="text-align: right;">Events</th>
                <th style="text-align: right;">Blocked</th>
                <th style="text-align: center;">Threat Score</th>
              </tr>
            </thead>
            <tbody>
              {{range $i, $a := .TopAttackers}}
              <tr>
                <td class="rank">{{inc $i}}</td>
                <td class="ip-cell">{{$a.IP}}</td>
                <td>{{$a.Country}}</td>
                <td style="text-align: right;">
                  <strong>{{$a.AttackCount}}</strong>
                  <div class="bar-container"><div class="bar bar-orange" style="width: {{$a.Percentage}}%;"></div></div>
                </td>
                <td style="text-align: right;">{{$a.BlockedCount}}</td>
                <td style="text-align: center;">
                  <span class="score-badge {{if gt $a.ThreatScore 70}}score-high{{else if gt $a.ThreatScore 40}}score-medium{{else}}score-low{{end}}">{{$a.ThreatScore}}</span>
                </td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
      </div>
      {{end}}

      {{if .TopTargets}}
      <!-- Top Targets -->
      <div class="section">
        <h2 class="section-title">Most Targeted Resources</h2>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th class="rank">#</th>
                <th>Hostname</th>
                <th style="text-align: right;">Attacks</th>
                <th style="text-align: right;">Blocked</th>
              </tr>
            </thead>
            <tbody>
              {{range $i, $t := .TopTargets}}
              <tr>
                <td class="rank">{{inc $i}}</td>
                <td class="ip-cell">{{$t.Hostname}}</td>
                <td style="text-align: right;">
                  <strong>{{$t.AttackCount}}</strong>
                  <div class="bar-container"><div class="bar bar-red" style="width: {{$t.Percentage}}%;"></div></div>
                </td>
                <td style="text-align: right;">{{$t.BlockedCount}}</td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
      </div>
      {{end}}

      {{if .TopCountries}}
      <!-- Geographic Distribution -->
      <div class="section">
        <h2 class="section-title">Geographic Distribution</h2>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th class="rank">#</th>
                <th>Country</th>
                <th style="text-align: right;">Events</th>
                <th style="text-align: right;">% of Total</th>
              </tr>
            </thead>
            <tbody>
              {{range $i, $c := .TopCountries}}
              <tr>
                <td class="rank">{{inc $i}}</td>
                <td>{{$c.Country}}</td>
                <td style="text-align: right;">
                  <strong>{{$c.Count}}</strong>
                  <div class="bar-container"><div class="bar bar-blue" style="width: {{$c.Percentage}}%;"></div></div>
                </td>
                <td style="text-align: right;">{{$c.PercentFormatted}}%</td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
      </div>
      {{end}}

      {{if .TopAttackTypes}}
      <!-- Attack Types -->
      <div class="section">
        <h2 class="section-title">Attack Categories</h2>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th class="rank">#</th>
                <th>Attack Type</th>
                <th style="text-align: right;">Count</th>
                <th style="text-align: right;">% of Total</th>
              </tr>
            </thead>
            <tbody>
              {{range $i, $at := .TopAttackTypes}}
              <tr>
                <td class="rank">{{inc $i}}</td>
                <td>{{$at.Type}}</td>
                <td style="text-align: right;">
                  <strong>{{$at.Count}}</strong>
                  <div class="bar-container"><div class="bar bar-orange" style="width: {{$at.Percentage}}%;"></div></div>
                </td>
                <td style="text-align: right;">{{$at.PercentFormatted}}%</td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
      </div>
      {{end}}

      <!-- Additional Metrics -->
      <div class="section">
        <h2 class="section-title">Additional Metrics</h2>
        <div class="table-container" style="padding: 20px;">
          <div class="metric-row">
            <span class="metric-label">Average Events per Hour</span>
            <span class="metric-value">{{.EventsPerHour}}</span>
          </div>
          <div class="metric-row">
            <span class="metric-label">Peak Hour Activity</span>
            <span class="metric-value">{{.PeakHour}}</span>
          </div>
          <div class="metric-row">
            <span class="metric-label">Block Rate</span>
            <span class="metric-value">{{.BlockRate}}%</span>
          </div>
          <div class="metric-row">
            <span class="metric-label">Active Bans (Total)</span>
            <span class="metric-value">{{.ActiveBans}}</span>
          </div>
        </div>
      </div>
    </div>

    <div class="footer">
      <div class="footer-brand">VIGILANCE X</div>
      <div>Security Operations Center • Generated {{.GeneratedAt}}</div>
    </div>
  </div>
</body>
</html>`

	funcMap := template.FuncMap{
		"inc": func(i int) int { return i + 1 },
	}

	t, _ := template.New("report").Funcs(funcMap).Parse(tmpl)
	var buf bytes.Buffer

	period := data.EndDate.Format("January 2, 2006")
	if data.StartDate != data.EndDate {
		period = fmt.Sprintf("%s to %s", data.StartDate.Format("January 2"), data.EndDate.Format("January 2, 2006"))
	}

	// Calculate max for percentage bars
	var maxAttacks int64 = 1
	for _, a := range data.TopAttackers {
		if a.AttackCount > maxAttacks {
			maxAttacks = a.AttackCount
		}
	}

	// Enhance attackers with percentage
	type EnhancedAttacker struct {
		IP           string
		Country      string
		AttackCount  int64
		BlockedCount int64
		ThreatScore  int
		Percentage   int64
	}
	enhancedAttackers := make([]EnhancedAttacker, 0, len(data.TopAttackers))
	for _, a := range data.TopAttackers {
		enhancedAttackers = append(enhancedAttackers, EnhancedAttacker{
			IP:           a.IP,
			Country:      a.Country,
			AttackCount:  a.AttackCount,
			BlockedCount: a.BlockedCount,
			ThreatScore:  a.ThreatScore,
			Percentage:   (a.AttackCount * 100) / maxAttacks,
		})
	}

	// Calculate events per hour
	hours := data.EndDate.Sub(data.StartDate).Hours()
	if hours < 1 {
		hours = 24
	}
	eventsPerHour := float64(data.TotalEvents) / hours

	t.Execute(&buf, map[string]interface{}{
		"ReportType":              reportType,
		"Period":                  period,
		"TotalEvents":             data.TotalEvents,
		"TotalEventsFormatted":    formatNumberWithCommas(data.TotalEvents),
		"BlockedEvents":           data.BlockedEvents,
		"BlockedEventsFormatted":  formatNumberWithCommas(data.BlockedEvents),
		"CriticalEvents":          data.CriticalEvents,
		"CriticalEventsFormatted": formatNumberWithCommas(data.CriticalEvents),
		"HighEvents":              data.HighEvents,
		"HighEventsFormatted":     formatNumberWithCommas(data.HighEvents),
		"MediumEvents":            data.MediumEvents,
		"MediumEventsFormatted":   formatNumberWithCommas(data.MediumEvents),
		"LowEvents":               data.LowEvents,
		"LowEventsFormatted":      formatNumberWithCommas(data.LowEvents),
		"UniqueIPs":               data.UniqueIPs,
		"UniqueIPsFormatted":      formatNumberWithCommas(data.UniqueIPs),
		"NewBans":                 data.NewBans,
		"NewBansFormatted":        formatNumberWithCommas(data.NewBans),
		"BlockRate":               fmt.Sprintf("%.1f", blockRate),
		"TopAttackers":            enhancedAttackers,
		"TopTargets":              data.TopTargets,
		"TopCountries":            data.TopCountries,
		"TopAttackTypes":          data.TopAttackTypes,
		"EventsPerHour":           fmt.Sprintf("%.1f", eventsPerHour),
		"PeakHour":                data.PeakHour,
		"ActiveBans":              formatNumberWithCommas(data.ActiveBans),
		"GeneratedAt":             time.Now().Format("2006-01-02 15:04:05 MST"),
	})

	return buf.String()
}

// formatNumberWithCommas formats a number with thousand separators
func formatNumberWithCommas(n int) string {
	str := fmt.Sprintf("%d", n)
	if len(str) <= 3 {
		return str
	}

	var result []byte
	for i, c := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

// renderHTMLAlert generates an HTML alert email
func renderHTMLAlert(data *entity.AlertData, alertType string, color string) string {
	tmpl := `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>VIGILANCE X Alert</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
  <div style="background: {{.Color}}; color: white; padding: 25px; text-align: center;">
    <h1 style="margin: 0; font-size: 20px;">{{.AlertType}}</h1>
  </div>

  <div style="padding: 30px; background: #f9fafb;">
    <div style="background: white; border-radius: 8px; padding: 25px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
      <table style="width: 100%; border-collapse: collapse;">
        <tr>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; color: #6b7280; width: 120px;">Time</td>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; font-weight: 500;">{{.Timestamp}}</td>
        </tr>
        <tr>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; color: #6b7280;">Source IP</td>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; font-family: monospace; font-weight: 500;">{{.SourceIP}}</td>
        </tr>
        <tr>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; color: #6b7280;">Country</td>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb;">{{.Country}}</td>
        </tr>
        {{if .Target}}
        <tr>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; color: #6b7280;">Target</td>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb;">{{.Target}}</td>
        </tr>
        {{end}}
        {{if .RuleName}}
        <tr>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; color: #6b7280;">Rule</td>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb;">{{.RuleID}} - {{.RuleName}}</td>
        </tr>
        {{end}}
        <tr>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; color: #6b7280;">Threat Score</td>
          <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb;">
            <span style="background: {{if gt .ThreatScore 70}}#fef2f2{{else if gt .ThreatScore 40}}#fef9c3{{else}}#f0fdf4{{end}}; color: {{if gt .ThreatScore 70}}#dc2626{{else if gt .ThreatScore 40}}#ca8a04{{else}}#16a34a{{end}}; padding: 4px 12px; border-radius: 4px; font-weight: 500;">{{.ThreatScore}}/100</span>
          </td>
        </tr>
      </table>

      {{if .Details}}
      <div style="margin-top: 20px;">
        <div style="color: #6b7280; font-size: 12px; margin-bottom: 8px;">Details</div>
        <div style="background: #f3f4f6; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 13px; white-space: pre-wrap;">{{.Details}}</div>
      </div>
      {{end}}
    </div>
  </div>

  <div style="padding: 20px; text-align: center; color: #9ca3af; font-size: 12px;">
    VIGILANCE X Security Operations Center
  </div>
</body>
</html>`

	t, _ := template.New("alert").Parse(tmpl)
	var buf bytes.Buffer

	t.Execute(&buf, map[string]interface{}{
		"AlertType":   alertType,
		"Color":       color,
		"Timestamp":   data.Timestamp.Format("2006-01-02 15:04:05"),
		"SourceIP":    data.SourceIP,
		"Country":     data.Country,
		"Target":      data.Target,
		"RuleID":      data.RuleID,
		"RuleName":    data.RuleName,
		"ThreatScore": data.ThreatScore,
		"Details":     data.Details,
	})

	return buf.String()
}
