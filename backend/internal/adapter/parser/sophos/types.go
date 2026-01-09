// Package sophos provides XML parser for Sophos XGS log definitions.
// It reads vigilanceX_XGS_decoders.xml and vigilanceX_XGS_rules.xml
// to configure the log parsing and detection pipeline.
package sophos

import (
	"encoding/xml"
	"regexp"
	"time"
)

// ============================================================
// DECODER TYPES - vigilanceX_XGS_decoders.xml
// ============================================================

// DecodersConfig represents the root element of decoders XML
type DecodersConfig struct {
	XMLName   xml.Name        `xml:"vigilancex_decoders"`
	Version   string          `xml:"version,attr"`
	Metadata  DecoderMetadata `xml:"metadata"`
	Prematch  Prematch        `xml:"prematch"`
	Groups    []FieldGroup    `xml:"field_group"`
	loadedAt  time.Time
	fieldsMap map[string]*Field // Cache for quick field lookup
}

// DecoderMetadata contains decoder file metadata
type DecoderMetadata struct {
	Name          string   `xml:"name"`
	Description   string   `xml:"description"`
	Author        string   `xml:"author"`
	SophosVersion string   `xml:"sophos_version"`
	LogFormats    []string `xml:"log_formats>format"`
	TotalFields   int      `xml:"total_fields"`
}

// Prematch defines the pattern to identify Sophos XGS logs
type Prematch struct {
	Pattern     string `xml:"pattern"`
	Description string `xml:"description"`
	compiled    *regexp.Regexp
}

// FieldGroup represents a logical grouping of fields
type FieldGroup struct {
	Name        string  `xml:"name,attr"`
	Priority    int     `xml:"priority,attr"`
	Description string  `xml:"description"`
	Fields      []Field `xml:"field"`
}

// Field represents a single extractable field from Sophos logs
type Field struct {
	Name           string          `xml:"name,attr"`
	Required       bool            `xml:"required,attr"`
	Type           string          `xml:"type"`
	Regex          string          `xml:"regex"`
	Alternatives   string          `xml:"alternatives"`
	ClickHouseType string          `xml:"clickhouse_type"`
	Description    string          `xml:"description"`
	Example        string          `xml:"example"`
	Index          string          `xml:"index"`
	Validation     string          `xml:"validation"`
	Default        string          `xml:"default"`
	VXMapping      string          `xml:"vx_mapping"`
	VXBinding      bool            `xml:"vx_binding"`
	Normalization  string          `xml:"normalization"`
	AllowedValues  []string        `xml:"allowed_values>value"`
	Compliance     *ComplianceSpec `xml:"compliance_check"`
	compiled       *regexp.Regexp
	altNames       []string
}

// ComplianceSpec defines compliance requirements for a field
type ComplianceSpec struct {
	Deprecated  string `xml:"deprecated"`
	Recommended string `xml:"recommended"`
}

// NormalizationMap defines value mappings for normalization
type NormalizationMap struct {
	From string `xml:"from,attr"`
	To   string `xml:"to,attr"`
}

// ============================================================
// RULES TYPES - vigilanceX_XGS_rules.xml
// ============================================================

// RulesConfig represents the root element of rules XML
type RulesConfig struct {
	XMLName    xml.Name      `xml:"vigilancex_rules"`
	Version    string        `xml:"version,attr"`
	Metadata   RulesMetadata `xml:"metadata"`
	RuleGroups []RuleGroup   `xml:"rule_group"`
	loadedAt   time.Time
	rulesMap   map[string]*Rule // Cache for quick rule lookup by ID
}

// RulesMetadata contains rules file metadata
type RulesMetadata struct {
	Name          string           `xml:"name"`
	Description   string           `xml:"description"`
	Author        string           `xml:"author"`
	TotalRules    int              `xml:"total_rules"`
	MitreCoverage []MitreTechnique `xml:"mitre_coverage>technique"`
}

// MitreTechnique represents a MITRE ATT&CK technique
type MitreTechnique struct {
	ID   string `xml:"id,attr"`
	Name string `xml:",chardata"`
}

// RuleGroup represents a category of detection rules
type RuleGroup struct {
	Name        string `xml:"name,attr"`
	IDRange     string `xml:"id_range,attr"`
	Description string `xml:"description"`
	Rules       []Rule `xml:"rule"`
}

// Rule represents a single detection rule
type Rule struct {
	ID                string      `xml:"id,attr"`
	Level             int         `xml:"level,attr"`
	IfParent          string      `xml:"if_parent"`
	DecodedAs         string      `xml:"decoded_as"`
	Match             *RuleMatch  `xml:"match"`
	Frequency         int         `xml:"frequency"`
	Timeframe         int         `xml:"timeframe"`
	GroupBy           string      `xml:"group_by"`
	DistinctUsers     int         `xml:"distinct_users"`
	Description       string      `xml:"description"`
	VXCategory        string      `xml:"vx_category"`
	ComplianceCheck   string      `xml:"compliance_check"`
	ComplianceWarning string      `xml:"compliance_warning"`
	Mitre             *RuleMitre  `xml:"mitre"`
	VXAction          *RuleAction `xml:"vx_action"`
}

// RuleMatch defines conditions for rule triggering
type RuleMatch struct {
	Fields []MatchField `xml:"field"`
}

// MatchField defines a single field match condition
type MatchField struct {
	Name     string `xml:"name,attr"`
	Operator string `xml:"operator,attr"` // eq, in, contains, regex, not_empty, gte, lte
	Value    string `xml:",chardata"`
}

// RuleMitre contains MITRE ATT&CK mappings for a rule
type RuleMitre struct {
	Techniques []MitreTechnique `xml:"technique"`
}

// RuleAction defines actions to take when rule triggers
type RuleAction struct {
	Types           []string `xml:"type"`
	Duration        string   `xml:"duration"`
	Severity        string   `xml:"severity"`
	Progressive     bool     `xml:"progressive"`
	SyncSophos      bool     `xml:"sync_sophos"`
	Notify          bool     `xml:"notify"`
	Group           string   `xml:"group"`
	Providers       string   `xml:"providers"`
	IsolateEndpoint bool     `xml:"isolate_endpoint"`
}

// ============================================================
// RUNTIME TYPES - Used during log processing
// ============================================================

// ParsedLog represents a parsed Sophos XGS log entry
type ParsedLog struct {
	Fields    map[string]string
	Timestamp time.Time
	LogType   string
	RawLog    string
}

// TriggeredRule represents a rule that matched a log entry
type TriggeredRule struct {
	RuleID      string
	Level       int
	Description string
	Category    string
	Mitre       []string
	Action      *RuleAction
	MatchedAt   time.Time
}

// FieldValidationResult represents the result of field validation
type FieldValidationResult struct {
	Field   string
	Value   string
	Valid   bool
	Error   string
	Warning string
}

// ============================================================
// STATISTICS TYPES
// ============================================================

// ParserStats tracks parser performance metrics
type ParserStats struct {
	TotalFieldsLoaded   int           `json:"total_fields_loaded"`
	TotalRulesLoaded    int           `json:"total_rules_loaded"`
	TotalGroupsLoaded   int           `json:"total_groups_loaded"`
	DecodersLoadedAt    time.Time     `json:"decoders_loaded_at"`
	RulesLoadedAt       time.Time     `json:"rules_loaded_at"`
	LastParseTime       time.Duration `json:"last_parse_time"`
	TotalLogsParsed     int64         `json:"total_logs_parsed"`
	TotalRulesTriggered int64         `json:"total_rules_triggered"`
}
