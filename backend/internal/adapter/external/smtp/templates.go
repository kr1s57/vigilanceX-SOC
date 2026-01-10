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
func renderHTMLReport(data *entity.ReportData, reportType string) string {
	tmpl := `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>VIGILANCE X {{.ReportType}} Report</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 700px; margin: 0 auto;">
  <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px;">
    <h1 style="margin: 0; font-size: 24px;">VIGILANCE X</h1>
    <p style="margin: 5px 0 0 0; opacity: 0.9;">{{.ReportType}} Security Report</p>
    <p style="margin: 5px 0 0 0; font-size: 14px; opacity: 0.7;">{{.Period}}</p>
  </div>

  <div style="padding: 30px; background: #f9fafb;">
    <h2 style="color: #1a1a2e; margin: 0 0 20px 0; font-size: 18px;">Security Overview</h2>

    <div style="display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 30px;">
      <div style="flex: 1; min-width: 140px; background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
        <div style="font-size: 28px; font-weight: bold; color: #1a1a2e;">{{.TotalEvents}}</div>
        <div style="font-size: 12px; color: #6b7280;">Total Events</div>
      </div>
      <div style="flex: 1; min-width: 140px; background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
        <div style="font-size: 28px; font-weight: bold; color: #dc2626;">{{.BlockedEvents}}</div>
        <div style="font-size: 12px; color: #6b7280;">Blocked</div>
      </div>
      <div style="flex: 1; min-width: 140px; background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
        <div style="font-size: 28px; font-weight: bold; color: #f97316;">{{.CriticalEvents}}</div>
        <div style="font-size: 12px; color: #6b7280;">Critical</div>
      </div>
      <div style="flex: 1; min-width: 140px; background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
        <div style="font-size: 28px; font-weight: bold; color: #8b5cf6;">{{.NewBans}}</div>
        <div style="font-size: 12px; color: #6b7280;">New Bans</div>
      </div>
    </div>

    {{if .TopAttackers}}
    <h2 style="color: #1a1a2e; margin: 0 0 15px 0; font-size: 18px;">Top Attacking IPs</h2>
    <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
      <thead>
        <tr style="background: #f3f4f6;">
          <th style="padding: 12px; text-align: left; font-size: 12px; color: #6b7280;">IP Address</th>
          <th style="padding: 12px; text-align: left; font-size: 12px; color: #6b7280;">Country</th>
          <th style="padding: 12px; text-align: right; font-size: 12px; color: #6b7280;">Events</th>
          <th style="padding: 12px; text-align: right; font-size: 12px; color: #6b7280;">Score</th>
        </tr>
      </thead>
      <tbody>
        {{range .TopAttackers}}
        <tr style="border-top: 1px solid #e5e7eb;">
          <td style="padding: 12px; font-family: monospace;">{{.IP}}</td>
          <td style="padding: 12px;">{{.Country}}</td>
          <td style="padding: 12px; text-align: right;">{{.AttackCount}}</td>
          <td style="padding: 12px; text-align: right;"><span style="background: {{if gt .ThreatScore 70}}#fef2f2{{else if gt .ThreatScore 40}}#fef9c3{{else}}#f0fdf4{{end}}; color: {{if gt .ThreatScore 70}}#dc2626{{else if gt .ThreatScore 40}}#ca8a04{{else}}#16a34a{{end}}; padding: 2px 8px; border-radius: 4px; font-size: 12px;">{{.ThreatScore}}</span></td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{end}}
  </div>

  <div style="padding: 20px; text-align: center; color: #9ca3af; font-size: 12px; background: #f3f4f6;">
    Generated by VIGILANCE X Security Operations Center
  </div>
</body>
</html>`

	t, _ := template.New("report").Parse(tmpl)
	var buf bytes.Buffer

	period := data.EndDate.Format("2006-01-02")
	if data.StartDate != data.EndDate {
		period = fmt.Sprintf("%s to %s", data.StartDate.Format("2006-01-02"), data.EndDate.Format("2006-01-02"))
	}

	t.Execute(&buf, map[string]interface{}{
		"ReportType":     reportType,
		"Period":         period,
		"TotalEvents":    data.TotalEvents,
		"BlockedEvents":  data.BlockedEvents,
		"CriticalEvents": data.CriticalEvents,
		"NewBans":        data.NewBans,
		"TopAttackers":   data.TopAttackers,
	})

	return buf.String()
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
