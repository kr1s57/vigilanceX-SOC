package sophos

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RulesParser handles parsing of Sophos XGS detection rules
type RulesParser struct {
	config     *RulesConfig
	mu         sync.RWMutex
	parentTree map[string][]*Rule // Rules indexed by parent ID
	compiled   map[string]*regexp.Regexp
}

// NewRulesParser creates a new rules parser instance
func NewRulesParser() *RulesParser {
	return &RulesParser{
		parentTree: make(map[string][]*Rule),
		compiled:   make(map[string]*regexp.Regexp),
	}
}

// LoadFromFile loads rule definitions from XML file
func (p *RulesParser) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rules file: %w", err)
	}

	return p.LoadFromBytes(data)
}

// LoadFromBytes loads rule definitions from XML bytes
func (p *RulesParser) LoadFromBytes(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var config RulesConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parse rules XML: %w", err)
	}

	config.loadedAt = time.Now()
	config.rulesMap = make(map[string]*Rule)

	// Build rules map and parent tree
	p.parentTree = make(map[string][]*Rule)

	for i := range config.RuleGroups {
		for j := range config.RuleGroups[i].Rules {
			rule := &config.RuleGroups[i].Rules[j]
			config.rulesMap[rule.ID] = rule

			// Build parent tree for hierarchical evaluation
			if rule.IfParent != "" {
				p.parentTree[rule.IfParent] = append(p.parentTree[rule.IfParent], rule)
			}
		}
	}

	p.config = &config
	return nil
}

// Compile compiles all regex patterns in rules
func (p *RulesParser) Compile() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.config == nil {
		return fmt.Errorf("no rules config loaded")
	}

	p.compiled = make(map[string]*regexp.Regexp)

	for _, group := range p.config.RuleGroups {
		for _, rule := range group.Rules {
			if rule.Match == nil {
				continue
			}

			for _, field := range rule.Match.Fields {
				if field.Operator == "regex" {
					key := fmt.Sprintf("%s_%s", rule.ID, field.Name)
					re, err := regexp.Compile(field.Value)
					if err != nil {
						return fmt.Errorf("compile rule %s field %s regex: %w", rule.ID, field.Name, err)
					}
					p.compiled[key] = re
				}
			}
		}
	}

	return nil
}

// EvaluateLog evaluates a parsed log against all rules
func (p *RulesParser) EvaluateLog(log *ParsedLog) []TriggeredRule {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	var triggered []TriggeredRule

	// Find root rules (no parent or decoded_as match)
	for _, group := range p.config.RuleGroups {
		for _, rule := range group.Rules {
			// Check decoded_as for root rules
			if rule.DecodedAs != "" {
				if p.matchRule(&rule, log) {
					triggered = append(triggered, p.createTriggeredRule(&rule))

					// Check child rules
					children := p.evaluateChildren(&rule, log)
					triggered = append(triggered, children...)
				}
				continue
			}

			// Skip rules with parents (handled by evaluateChildren)
			if rule.IfParent != "" {
				continue
			}

			// Evaluate standalone rules
			if p.matchRule(&rule, log) {
				triggered = append(triggered, p.createTriggeredRule(&rule))
			}
		}
	}

	return triggered
}

// evaluateChildren recursively evaluates child rules
func (p *RulesParser) evaluateChildren(parent *Rule, log *ParsedLog) []TriggeredRule {
	var triggered []TriggeredRule

	children, ok := p.parentTree[parent.ID]
	if !ok {
		return triggered
	}

	for _, child := range children {
		if p.matchRule(child, log) {
			triggered = append(triggered, p.createTriggeredRule(child))

			// Recursively check grandchildren
			grandchildren := p.evaluateChildren(child, log)
			triggered = append(triggered, grandchildren...)
		}
	}

	return triggered
}

// matchRule checks if a log matches a rule's conditions
func (p *RulesParser) matchRule(rule *Rule, log *ParsedLog) bool {
	if rule.Match == nil {
		return true // No conditions = always match (for parent rules)
	}

	for _, field := range rule.Match.Fields {
		if !p.matchField(&field, rule.ID, log) {
			return false // AND logic: all fields must match
		}
	}

	return true
}

// matchField checks if a log field matches a condition
func (p *RulesParser) matchField(field *MatchField, ruleID string, log *ParsedLog) bool {
	value, ok := log.Fields[field.Name]
	if !ok && field.Operator != "not_empty" {
		return false
	}

	expected := field.Value
	valueLower := strings.ToLower(value)

	switch field.Operator {
	case "", "eq":
		return strings.EqualFold(value, expected)

	case "in":
		values := strings.Split(expected, ",")
		for _, v := range values {
			if strings.EqualFold(value, strings.TrimSpace(v)) {
				return true
			}
		}
		return false

	case "contains":
		patterns := strings.Split(strings.ToLower(expected), ",")
		for _, pattern := range patterns {
			if strings.Contains(valueLower, strings.TrimSpace(pattern)) {
				return true
			}
		}
		return false

	case "regex":
		key := fmt.Sprintf("%s_%s", ruleID, field.Name)
		if re, ok := p.compiled[key]; ok {
			return re.MatchString(value)
		}
		// Try compiling on the fly if not precompiled
		re, err := regexp.Compile(expected)
		if err != nil {
			return false
		}
		return re.MatchString(value)

	case "not_empty":
		return value != ""

	case "gte":
		v, err1 := strconv.ParseFloat(value, 64)
		e, err2 := strconv.ParseFloat(expected, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		return v >= e

	case "lte":
		v, err1 := strconv.ParseFloat(value, 64)
		e, err2 := strconv.ParseFloat(expected, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		return v <= e

	default:
		return false
	}
}

// createTriggeredRule creates a TriggeredRule from a matched Rule
func (p *RulesParser) createTriggeredRule(rule *Rule) TriggeredRule {
	tr := TriggeredRule{
		RuleID:      rule.ID,
		Level:       rule.Level,
		Description: rule.Description,
		Category:    rule.VXCategory,
		MatchedAt:   time.Now(),
		Action:      rule.VXAction,
	}

	if rule.Mitre != nil {
		for _, tech := range rule.Mitre.Techniques {
			tr.Mitre = append(tr.Mitre, tech.ID)
		}
	}

	return tr
}

// GetRule returns a rule by ID
func (p *RulesParser) GetRule(id string) *Rule {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	return p.config.rulesMap[id]
}

// GetRulesByLevel returns rules filtered by minimum level
func (p *RulesParser) GetRulesByLevel(minLevel int) []Rule {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	var filtered []Rule
	for _, group := range p.config.RuleGroups {
		for _, rule := range group.Rules {
			if rule.Level >= minLevel {
				filtered = append(filtered, rule)
			}
		}
	}
	return filtered
}

// GetRulesByCategory returns rules filtered by VX category
func (p *RulesParser) GetRulesByCategory(category string) []Rule {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	var filtered []Rule
	for _, group := range p.config.RuleGroups {
		for _, rule := range group.Rules {
			if strings.EqualFold(rule.VXCategory, category) {
				filtered = append(filtered, rule)
			}
		}
	}
	return filtered
}

// GetRulesWithAction returns rules that have a specific action type
func (p *RulesParser) GetRulesWithAction(actionType string) []Rule {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	var filtered []Rule
	for _, group := range p.config.RuleGroups {
		for _, rule := range group.Rules {
			if rule.VXAction == nil {
				continue
			}
			for _, t := range rule.VXAction.Types {
				if t == actionType {
					filtered = append(filtered, rule)
					break
				}
			}
		}
	}
	return filtered
}

// GetRulesWithMitre returns rules that have MITRE ATT&CK mappings
func (p *RulesParser) GetRulesWithMitre() []Rule {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	var filtered []Rule
	for _, group := range p.config.RuleGroups {
		for _, rule := range group.Rules {
			if rule.Mitre != nil && len(rule.Mitre.Techniques) > 0 {
				filtered = append(filtered, rule)
			}
		}
	}
	return filtered
}

// GetAllRuleGroups returns all rule groups
func (p *RulesParser) GetAllRuleGroups() []RuleGroup {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	return p.config.RuleGroups
}

// GetMetadata returns rules metadata
func (p *RulesParser) GetMetadata() *RulesMetadata {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	return &p.config.Metadata
}

// GetVersion returns the rules version
func (p *RulesParser) GetVersion() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return ""
	}

	return p.config.Version
}

// GetStats returns parser statistics
func (p *RulesParser) GetStats() *ParserStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := &ParserStats{}

	if p.config != nil {
		stats.RulesLoadedAt = p.config.loadedAt

		for _, group := range p.config.RuleGroups {
			stats.TotalRulesLoaded += len(group.Rules)
		}
	}

	return stats
}

// GenerateDetect2BanYAML generates Detect2Ban YAML scenarios from rules
func (p *RulesParser) GenerateDetect2BanYAML(minLevel int) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	var scenarios []string

	for _, group := range p.config.RuleGroups {
		for _, rule := range group.Rules {
			// Only generate for rules with actions and sufficient level
			if rule.Level < minLevel || rule.VXAction == nil {
				continue
			}

			// Skip rules that only alert/log
			hasBan := false
			for _, t := range rule.VXAction.Types {
				if t == "ban" {
					hasBan = true
					break
				}
			}
			if !hasBan {
				continue
			}

			yaml := p.ruleToYAML(&rule, group.Name)
			scenarios = append(scenarios, yaml)
		}
	}

	return scenarios
}

// ruleToYAML converts a Rule to Detect2Ban YAML format
func (p *RulesParser) ruleToYAML(rule *Rule, groupName string) string {
	var yaml strings.Builder

	yaml.WriteString(fmt.Sprintf("# Generated from rule %s\n", rule.ID))
	yaml.WriteString(fmt.Sprintf("name: %s_%s\n", groupName, strings.ReplaceAll(strings.ToLower(rule.VXCategory), " ", "_")))
	yaml.WriteString(fmt.Sprintf("description: \"%s\"\n", rule.Description))
	yaml.WriteString("enabled: true\n")
	yaml.WriteString(fmt.Sprintf("priority: %d\n\n", rule.Level))

	// Window
	if rule.Timeframe > 0 {
		yaml.WriteString(fmt.Sprintf("window: %ds\n\n", rule.Timeframe))
	} else {
		yaml.WriteString("window: 5m\n\n")
	}

	// Conditions
	yaml.WriteString("conditions:\n")
	if rule.Match != nil {
		for _, field := range rule.Match.Fields {
			yaml.WriteString(fmt.Sprintf("  - field: %s\n", field.Name))
			yaml.WriteString(fmt.Sprintf("    operator: %s\n", field.Operator))
			yaml.WriteString(fmt.Sprintf("    value: \"%s\"\n", field.Value))
		}
	}

	// Frequency threshold
	if rule.Frequency > 0 {
		yaml.WriteString(fmt.Sprintf("  - type: count\n    operator: gte\n    value: %d\n", rule.Frequency))
	}

	// Group by
	yaml.WriteString("\ngroup_by:\n")
	if rule.GroupBy != "" {
		yaml.WriteString(fmt.Sprintf("  - %s\n", rule.GroupBy))
	} else {
		yaml.WriteString("  - src_ip\n")
	}

	// Actions
	if rule.VXAction != nil {
		yaml.WriteString("\nactions:\n")
		for _, t := range rule.VXAction.Types {
			yaml.WriteString(fmt.Sprintf("  - type: %s\n", t))
			if t == "ban" && rule.VXAction.Duration != "" {
				yaml.WriteString(fmt.Sprintf("    duration: %s\n", rule.VXAction.Duration))
			}
			if rule.VXAction.SyncSophos {
				yaml.WriteString("    sync_sophos: true\n")
			}
			if rule.VXAction.Notify {
				yaml.WriteString("    notify: true\n")
			}
		}
	}

	// MITRE mapping as comment
	if rule.Mitre != nil && len(rule.Mitre.Techniques) > 0 {
		yaml.WriteString("\n# MITRE ATT&CK:\n")
		for _, tech := range rule.Mitre.Techniques {
			yaml.WriteString(fmt.Sprintf("#   - %s: %s\n", tech.ID, tech.Name))
		}
	}

	return yaml.String()
}

// GetMitreCoverage returns MITRE ATT&CK techniques covered by rules
func (p *RulesParser) GetMitreCoverage() map[string][]string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	coverage := make(map[string][]string)

	for _, group := range p.config.RuleGroups {
		for _, rule := range group.Rules {
			if rule.Mitre == nil {
				continue
			}
			for _, tech := range rule.Mitre.Techniques {
				coverage[tech.ID] = append(coverage[tech.ID], rule.ID)
			}
		}
	}

	return coverage
}
