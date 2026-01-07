package reports

import (
	"encoding/xml"
	"fmt"
	"time"
)

// XMLGenerator generates XML reports
type XMLGenerator struct{}

// NewXMLGenerator creates a new XML generator
func NewXMLGenerator() *XMLGenerator {
	return &XMLGenerator{}
}

// XMLReport represents the root XML structure
type XMLReport struct {
	XMLName     xml.Name      `xml:"VigilanceXReport"`
	Version     string        `xml:"version,attr"`
	GeneratedAt string        `xml:"generatedAt,attr"`
	Metadata    XMLMetadata   `xml:"Metadata"`
	Summary     XMLSummary    `xml:"Summary"`
	Events      *XMLEvents    `xml:"Events,omitempty"`
	WAF         *XMLWAF       `xml:"WAF,omitempty"`
	VPN         *XMLVPN       `xml:"VPN,omitempty"`
	Threats     *XMLThreats   `xml:"Threats,omitempty"`
	Bans        *XMLBans      `xml:"Bans,omitempty"`
	Attackers   *XMLAttackers `xml:"Attackers,omitempty"`
}

// XMLMetadata contains report metadata
type XMLMetadata struct {
	ReportType   string `xml:"ReportType"`
	Period       string `xml:"Period"`
	StartDate    string `xml:"StartDate"`
	EndDate      string `xml:"EndDate"`
	DatabaseSize string `xml:"DatabaseSize,omitempty"`
	TotalRecords uint64 `xml:"TotalRecords,omitempty"`
}

// XMLSummary contains executive summary data
type XMLSummary struct {
	TotalEvents    uint64  `xml:"TotalEvents"`
	BlockedEvents  uint64  `xml:"BlockedEvents"`
	BlockRate      float64 `xml:"BlockRate"`
	UniqueIPs      uint64  `xml:"UniqueIPs"`
	CriticalEvents uint64  `xml:"CriticalEvents"`
	HighEvents     uint64  `xml:"HighEvents"`
	MediumEvents   uint64  `xml:"MediumEvents"`
	LowEvents      uint64  `xml:"LowEvents"`
}

// XMLEvents contains event breakdown
type XMLEvents struct {
	ByType     []XMLEventType `xml:"ByType>Type"`
	BySeverity []XMLEventType `xml:"BySeverity>Severity"`
	ByAction   []XMLEventType `xml:"ByAction>Action"`
	TopTargets []XMLTarget    `xml:"TopTargets>Target"`
	TopRules   []XMLRule      `xml:"TopRules>Rule"`
}

// XMLEventType represents a type/severity/action breakdown
type XMLEventType struct {
	Name  string `xml:"name,attr"`
	Count uint64 `xml:"count,attr"`
}

// XMLTarget represents a targeted host
type XMLTarget struct {
	Hostname    string `xml:"hostname,attr"`
	AttackCount uint64 `xml:"attackCount,attr"`
	UniqueIPs   uint64 `xml:"uniqueIPs,attr"`
}

// XMLRule represents a triggered rule
type XMLRule struct {
	ID           string `xml:"id,attr"`
	Message      string `xml:"message,attr"`
	TriggerCount uint64 `xml:"triggerCount,attr"`
	UniqueIPs    uint64 `xml:"uniqueIPs,attr"`
}

// XMLWAF contains WAF/ModSecurity data
type XMLWAF struct {
	TotalDetections uint64          `xml:"TotalDetections"`
	BlockingEvents  uint64          `xml:"BlockingEvents"`
	UniqueRules     uint64          `xml:"UniqueRules"`
	AttackTypes     []XMLAttackType `xml:"AttackTypes>AttackType"`
	TopRules        []XMLRule       `xml:"TopRules>Rule"`
}

// XMLAttackType represents an attack type
type XMLAttackType struct {
	Type  string `xml:"type,attr"`
	Count uint64 `xml:"count,attr"`
}

// XMLVPN contains VPN statistics
type XMLVPN struct {
	TotalEvents    uint64 `xml:"TotalEvents"`
	Connections    uint64 `xml:"Connections"`
	Disconnections uint64 `xml:"Disconnections"`
	AuthFailures   uint64 `xml:"AuthFailures"`
	UniqueUsers    uint64 `xml:"UniqueUsers"`
}

// XMLThreats contains threat intelligence data
type XMLThreats struct {
	TotalTracked  uint64           `xml:"TotalTracked"`
	CriticalCount uint64           `xml:"CriticalCount"`
	HighCount     uint64           `xml:"HighCount"`
	MediumCount   uint64           `xml:"MediumCount"`
	LowCount      uint64           `xml:"LowCount"`
	TorExitNodes  uint64           `xml:"TorExitNodes"`
	Distribution  []XMLThreatLevel `xml:"Distribution>Level"`
}

// XMLThreatLevel represents a threat level distribution
type XMLThreatLevel struct {
	Level string `xml:"level,attr"`
	Count uint64 `xml:"count,attr"`
}

// XMLBans contains ban management data
type XMLBans struct {
	ActiveBans    uint64 `xml:"ActiveBans"`
	PermanentBans uint64 `xml:"PermanentBans"`
	ExpiredBans   uint64 `xml:"ExpiredBans"`
	NewBans       uint64 `xml:"NewBans"`
	Unbans        uint64 `xml:"Unbans"`
}

// XMLAttackers contains top attackers data
type XMLAttackers struct {
	Attackers []XMLAttacker `xml:"Attacker"`
	Countries []XMLCountry  `xml:"Countries>Country"`
}

// XMLAttacker represents an attacking IP
type XMLAttacker struct {
	IP           string `xml:"ip,attr"`
	Country      string `xml:"country,attr"`
	AttackCount  uint64 `xml:"attackCount,attr"`
	BlockedCount uint64 `xml:"blockedCount,attr"`
	UniqueRules  uint64 `xml:"uniqueRules,attr"`
}

// XMLCountry represents country statistics
type XMLCountry struct {
	Name        string `xml:"name,attr"`
	AttackCount uint64 `xml:"attackCount,attr"`
	UniqueIPs   uint64 `xml:"uniqueIPs,attr"`
}

// Generate creates an XML report from the report data
func (g *XMLGenerator) Generate(data *ReportData) ([]byte, error) {
	report := XMLReport{
		Version:     "1.0",
		GeneratedAt: data.GeneratedAt.Format(time.RFC3339),
		Metadata: XMLMetadata{
			ReportType: data.ReportType,
			Period:     data.Period,
			StartDate:  data.StartDate.Format(time.RFC3339),
			EndDate:    data.EndDate.Format(time.RFC3339),
		},
	}

	// Add database stats
	if data.DBStats != nil {
		report.Metadata.DatabaseSize = data.DBStats.DatabaseSize
		report.Metadata.TotalRecords = data.DBStats.TotalEvents
	}

	// Add summary
	if data.EventStats != nil {
		report.Summary = XMLSummary{
			TotalEvents:    data.EventStats.TotalEvents,
			BlockedEvents:  data.EventStats.BlockedEvents,
			BlockRate:      data.EventStats.BlockRate,
			UniqueIPs:      data.EventStats.UniqueIPs,
			CriticalEvents: data.EventStats.CriticalEvents,
			HighEvents:     data.EventStats.HighEvents,
			MediumEvents:   data.EventStats.MediumEvents,
			LowEvents:      data.EventStats.LowEvents,
		}

		// Events breakdown
		events := &XMLEvents{}

		for name, count := range data.EventStats.EventsByType {
			events.ByType = append(events.ByType, XMLEventType{Name: name, Count: count})
		}

		for name, count := range data.EventStats.EventsBySeverity {
			events.BySeverity = append(events.BySeverity, XMLEventType{Name: name, Count: count})
		}

		for name, count := range data.EventStats.EventsByAction {
			events.ByAction = append(events.ByAction, XMLEventType{Name: name, Count: count})
		}

		for _, target := range data.EventStats.TopTargets {
			events.TopTargets = append(events.TopTargets, XMLTarget{
				Hostname:    target.Hostname,
				AttackCount: target.AttackCount,
				UniqueIPs:   target.UniqueIPs,
			})
		}

		for _, rule := range data.EventStats.TopRules {
			events.TopRules = append(events.TopRules, XMLRule{
				ID:           rule.RuleID,
				Message:      rule.RuleMsg,
				TriggerCount: rule.TriggerCount,
				UniqueIPs:    rule.UniqueIPs,
			})
		}

		report.Events = events

		// Attackers
		if len(data.EventStats.TopAttackers) > 0 || len(data.EventStats.TopCountries) > 0 {
			attackers := &XMLAttackers{}

			for _, a := range data.EventStats.TopAttackers {
				attackers.Attackers = append(attackers.Attackers, XMLAttacker{
					IP:           a.IP,
					Country:      a.Country,
					AttackCount:  a.AttackCount,
					BlockedCount: a.BlockedCount,
					UniqueRules:  a.UniqueRules,
				})
			}

			for _, c := range data.EventStats.TopCountries {
				attackers.Countries = append(attackers.Countries, XMLCountry{
					Name:        c.Country,
					AttackCount: c.AttackCount,
					UniqueIPs:   c.UniqueIPs,
				})
			}

			report.Attackers = attackers
		}
	}

	// WAF/ModSec data
	if data.ModSecStats != nil {
		waf := &XMLWAF{
			TotalDetections: data.ModSecStats.TotalLogs,
			BlockingEvents:  data.ModSecStats.BlockingLogs,
			UniqueRules:     data.ModSecStats.UniqueRules,
		}

		for _, at := range data.ModSecStats.TopAttackTypes {
			waf.AttackTypes = append(waf.AttackTypes, XMLAttackType{
				Type:  at.Type,
				Count: at.Count,
			})
		}

		for _, rule := range data.ModSecStats.TopTriggeredRules {
			waf.TopRules = append(waf.TopRules, XMLRule{
				ID:           rule.RuleID,
				Message:      rule.RuleMsg,
				TriggerCount: rule.TriggerCount,
				UniqueIPs:    rule.UniqueIPs,
			})
		}

		report.WAF = waf
	}

	// VPN data
	if data.VPNStats != nil {
		report.VPN = &XMLVPN{
			TotalEvents:    data.VPNStats.TotalEvents,
			Connections:    data.VPNStats.Connections,
			Disconnections: data.VPNStats.Disconnections,
			AuthFailures:   data.VPNStats.AuthFailures,
			UniqueUsers:    data.VPNStats.UniqueUsers,
		}
	}

	// Threat intelligence data
	if data.ThreatStats != nil {
		threats := &XMLThreats{
			TotalTracked:  data.ThreatStats.TotalTracked,
			CriticalCount: data.ThreatStats.CriticalCount,
			HighCount:     data.ThreatStats.HighCount,
			MediumCount:   data.ThreatStats.MediumCount,
			LowCount:      data.ThreatStats.LowCount,
			TorExitNodes:  data.ThreatStats.TorExitNodes,
		}

		threats.Distribution = []XMLThreatLevel{
			{Level: "critical", Count: data.ThreatStats.CriticalCount},
			{Level: "high", Count: data.ThreatStats.HighCount},
			{Level: "medium", Count: data.ThreatStats.MediumCount},
			{Level: "low", Count: data.ThreatStats.LowCount},
		}

		report.Threats = threats
	}

	// Ban data
	if data.BanStats != nil {
		report.Bans = &XMLBans{
			ActiveBans:    data.BanStats.ActiveBans,
			PermanentBans: data.BanStats.PermanentBans,
			ExpiredBans:   data.BanStats.ExpiredBans,
			NewBans:       data.BanStats.NewBans,
			Unbans:        data.BanStats.Unbans,
		}
	}

	// Marshal to XML with indentation
	output, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}

	// Add XML header
	xmlHeader := []byte(xml.Header)
	result := append(xmlHeader, output...)

	return result, nil
}
