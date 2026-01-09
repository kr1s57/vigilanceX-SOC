package sophos

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Parser is the main Sophos XGS parser that combines decoders and rules
type Parser struct {
	Decoders *DecoderParser
	Rules    *RulesParser
	mu       sync.RWMutex
	loaded   bool
	stats    *ParserStats
}

// Config holds parser configuration
type Config struct {
	DecodersPath string // Path to vigilanceX_XGS_decoders.xml
	RulesPath    string // Path to vigilanceX_XGS_rules.xml
	ScenariosDir string // Directory for scenarios (default: same as decoders)
}

// New creates a new Sophos XGS parser
func New() *Parser {
	return &Parser{
		Decoders: NewDecoderParser(),
		Rules:    NewRulesParser(),
		stats:    &ParserStats{},
	}
}

// Load loads both decoders and rules from XML files
func (p *Parser) Load(cfg Config) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	start := time.Now()

	// Load decoders
	if err := p.Decoders.LoadFromFile(cfg.DecodersPath); err != nil {
		return fmt.Errorf("load decoders: %w", err)
	}

	// Compile decoder regex
	if err := p.Decoders.Compile(); err != nil {
		return fmt.Errorf("compile decoders: %w", err)
	}

	log.Printf("[SOPHOS-PARSER] Loaded decoders: %d fields from %s",
		len(p.Decoders.GetAllFields()), cfg.DecodersPath)

	// Load rules
	if err := p.Rules.LoadFromFile(cfg.RulesPath); err != nil {
		return fmt.Errorf("load rules: %w", err)
	}

	// Compile rule regex
	if err := p.Rules.Compile(); err != nil {
		return fmt.Errorf("compile rules: %w", err)
	}

	rulesStats := p.Rules.GetStats()
	log.Printf("[SOPHOS-PARSER] Loaded rules: %d rules from %s",
		rulesStats.TotalRulesLoaded, cfg.RulesPath)

	p.loaded = true
	p.stats.LastParseTime = time.Since(start)

	return nil
}

// LoadFromDir loads XML files from a directory
func (p *Parser) LoadFromDir(dir string) error {
	cfg := Config{
		DecodersPath: filepath.Join(dir, "vigilanceX_XGS_decoders.xml"),
		RulesPath:    filepath.Join(dir, "vigilanceX_XGS_rules.xml"),
		ScenariosDir: dir,
	}
	return p.Load(cfg)
}

// IsLoaded returns whether the parser has loaded configurations
func (p *Parser) IsLoaded() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.loaded
}

// ParseAndEvaluate parses a log and evaluates it against all rules
func (p *Parser) ParseAndEvaluate(rawLog string) (*ParsedLog, []TriggeredRule, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.loaded {
		return nil, nil, fmt.Errorf("parser not loaded")
	}

	// Check if it's a Sophos log
	if !p.Decoders.IsSophosLog(rawLog) {
		return nil, nil, fmt.Errorf("not a Sophos XGS log")
	}

	// Parse the log
	parsed, err := p.Decoders.ParseLog(rawLog)
	if err != nil {
		return nil, nil, fmt.Errorf("parse log: %w", err)
	}

	// Evaluate against rules
	triggered := p.Rules.EvaluateLog(parsed)

	// Update stats
	p.stats.TotalLogsParsed++
	p.stats.TotalRulesTriggered += int64(len(triggered))

	return parsed, triggered, nil
}

// GetStats returns combined parser statistics
func (p *Parser) GetStats() *ParserStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	decoderStats := p.Decoders.GetStats()
	rulesStats := p.Rules.GetStats()

	return &ParserStats{
		TotalFieldsLoaded:   decoderStats.TotalFieldsLoaded,
		TotalRulesLoaded:    rulesStats.TotalRulesLoaded,
		TotalGroupsLoaded:   decoderStats.TotalGroupsLoaded,
		DecodersLoadedAt:    decoderStats.DecodersLoadedAt,
		RulesLoadedAt:       rulesStats.RulesLoadedAt,
		LastParseTime:       p.stats.LastParseTime,
		TotalLogsParsed:     p.stats.TotalLogsParsed,
		TotalRulesTriggered: p.stats.TotalRulesTriggered,
	}
}

// GenerateVectorConfig generates Vector.toml transform configuration
func (p *Parser) GenerateVectorConfig() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.loaded {
		return ""
	}

	var config strings.Builder

	config.WriteString("# ============================================================\n")
	config.WriteString("# VIGILANCE X - Sophos XGS Parser Configuration\n")
	config.WriteString("# Auto-generated from vigilanceX_XGS_decoders.xml\n")
	config.WriteString(fmt.Sprintf("# Version: %s\n", p.Decoders.GetVersion()))
	config.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().Format(time.RFC3339)))
	config.WriteString("# ============================================================\n\n")

	// Transform: parse_sophos_extended
	config.WriteString("[transforms.parse_sophos_xgs]\n")
	config.WriteString("type = \"remap\"\n")
	config.WriteString("inputs = [\"syslog_udp\", \"syslog_tcp\"]\n")
	config.WriteString("source = '''\n")

	// Add prematch check
	config.WriteString("# Prematch: Verify Sophos XGS log format\n")
	if meta := p.Decoders.GetMetadata(); meta != nil {
		config.WriteString(fmt.Sprintf("# %s\n", meta.Description))
	}
	config.WriteString(".is_sophos = match(string!(.message), r'^device_name=\"\\w+\"\\s+timestamp=')\n")
	config.WriteString("if !.is_sophos {\n")
	config.WriteString("  abort\n")
	config.WriteString("}\n\n")

	// Parse KVP
	config.WriteString("# Parse Key-Value Pairs\n")
	config.WriteString(".raw_message = string!(.message)\n")
	config.WriteString(".parsed = parse_key_value!(.raw_message, key_value_delimiter: \"=\", field_delimiter: \" \")\n\n")

	// Generate field extraction by group
	for _, group := range p.Decoders.GetFieldGroups() {
		config.WriteString(fmt.Sprintf("# === %s (Priority %d) ===\n", strings.ToUpper(group.Name), group.Priority))

		for _, field := range group.Fields {
			p.writeFieldExtraction(&config, &field)
		}
		config.WriteString("\n")
	}

	// Add timestamp parsing
	config.WriteString("# Parse timestamp\n")
	config.WriteString("if .timestamp != \"\" {\n")
	config.WriteString("  .parsed_timestamp = parse_timestamp!(.timestamp, \"%Y-%m-%dT%H:%M:%S%z\") ?? now()\n")
	config.WriteString("} else {\n")
	config.WriteString("  .parsed_timestamp = now()\n")
	config.WriteString("}\n\n")

	// Add event_id and ingested_at
	config.WriteString("# Add VigilanceX metadata\n")
	config.WriteString(".event_id = uuid_v4()\n")
	config.WriteString(".ingested_at = now()\n")
	config.WriteString(".raw_log = .raw_message\n")

	config.WriteString("'''\n\n")

	// Add categorization transform
	config.WriteString(p.generateCategorizationTransform())

	return config.String()
}

// writeFieldExtraction writes VRL code for a single field extraction
func (p *Parser) writeFieldExtraction(config *strings.Builder, field *Field) {
	// Primary field name
	config.WriteString(fmt.Sprintf(".%s = get(.parsed, \"%s\")", field.Name, field.Name))

	// Add alternatives
	if field.Alternatives != "" {
		alts := strings.Split(field.Alternatives, ",")
		for _, alt := range alts {
			alt = strings.TrimSpace(alt)
			if alt != "" {
				config.WriteString(fmt.Sprintf(" ?? get(.parsed, \"%s\")", alt))
			}
		}
	}

	// Add default value
	if field.Default != "" {
		config.WriteString(fmt.Sprintf(" ?? \"%s\"", field.Default))
	} else {
		config.WriteString(" ?? \"\"")
	}

	config.WriteString("\n")

	// Add type conversion based on field type
	switch field.Type {
	case "integer":
		config.WriteString(fmt.Sprintf(".%s = to_int(.%s) ?? 0\n", field.Name, field.Name))
	case "float":
		config.WriteString(fmt.Sprintf(".%s = to_float(.%s) ?? 0.0\n", field.Name, field.Name))
	case "port":
		config.WriteString(fmt.Sprintf(".%s = to_int(.%s) ?? 0\n", field.Name, field.Name))
		config.WriteString(fmt.Sprintf("if .%s > 65535 { .%s = 0 }\n", field.Name, field.Name))
	case "ipv4":
		config.WriteString(fmt.Sprintf("if !is_ipv4(string!(.%s)) { .%s = \"0.0.0.0\" }\n", field.Name, field.Name))
	}

	// Add normalization
	switch field.Normalization {
	case "uppercase":
		config.WriteString(fmt.Sprintf(".%s = upcase(string!(.%s))\n", field.Name, field.Name))
	case "lowercase":
		config.WriteString(fmt.Sprintf(".%s = downcase(string!(.%s))\n", field.Name, field.Name))
	}

	// Add VX mapping if defined
	if field.VXMapping != "" {
		config.WriteString(fmt.Sprintf(".%s = .%s\n", field.VXMapping, field.Name))
	}
}

// generateCategorizationTransform generates the categorization transform
func (p *Parser) generateCategorizationTransform() string {
	var config strings.Builder

	config.WriteString("[transforms.categorize_sophos_xgs]\n")
	config.WriteString("type = \"remap\"\n")
	config.WriteString("inputs = [\"parse_sophos_xgs\"]\n")
	config.WriteString("source = '''\n")

	config.WriteString("# Categorize based on log_type and message patterns\n")
	config.WriteString(".category = \"\"\n\n")

	// Group rules by VX category and log_type for efficient categorization
	categoryRules := make(map[string][]string)
	for _, group := range p.Rules.GetAllRuleGroups() {
		for _, rule := range group.Rules {
			if rule.VXCategory == "" || rule.Match == nil {
				continue
			}

			// Extract log_type condition if present
			for _, field := range rule.Match.Fields {
				if field.Name == "log_type" {
					logTypes := strings.Split(field.Value, ",")
					for _, lt := range logTypes {
						lt = strings.TrimSpace(lt)
						categoryRules[lt] = append(categoryRules[lt], rule.VXCategory)
					}
				}
			}
		}
	}

	// Generate categorization logic
	for logType, categories := range categoryRules {
		config.WriteString(fmt.Sprintf("if .log_type == \"%s\" {\n", logType))
		if len(categories) == 1 {
			config.WriteString(fmt.Sprintf("  .category = \"%s\"\n", categories[0]))
		} else {
			// Use first category as default
			config.WriteString(fmt.Sprintf("  .category = \"%s\"\n", categories[0]))
		}
		config.WriteString("}\n\n")
	}

	// Default category
	config.WriteString("if .category == \"\" {\n")
	config.WriteString("  .category = \"Unknown\"\n")
	config.WriteString("}\n")

	config.WriteString("'''\n")

	return config.String()
}

// ExportDetect2BanScenarios exports rules as Detect2Ban YAML scenarios
func (p *Parser) ExportDetect2BanScenarios(minLevel int) map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.loaded {
		return nil
	}

	scenarios := make(map[string]string)
	yamls := p.Rules.GenerateDetect2BanYAML(minLevel)

	for i, yaml := range yamls {
		// Extract scenario name from YAML
		lines := strings.Split(yaml, "\n")
		name := fmt.Sprintf("scenario_%d", i)
		for _, line := range lines {
			if strings.HasPrefix(line, "name:") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
				break
			}
		}
		scenarios[name+".yaml"] = yaml
	}

	return scenarios
}

// GetMitreCoverage returns MITRE ATT&CK coverage summary
func (p *Parser) GetMitreCoverage() map[string]int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.loaded {
		return nil
	}

	coverage := p.Rules.GetMitreCoverage()
	summary := make(map[string]int)

	for techID, ruleIDs := range coverage {
		summary[techID] = len(ruleIDs)
	}

	return summary
}
