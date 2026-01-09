package sophos

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DecoderParser handles parsing of Sophos XGS log definitions
type DecoderParser struct {
	config   *DecodersConfig
	mu       sync.RWMutex
	compiled bool
}

// NewDecoderParser creates a new decoder parser instance
func NewDecoderParser() *DecoderParser {
	return &DecoderParser{}
}

// LoadFromFile loads decoder definitions from XML file
func (p *DecoderParser) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read decoder file: %w", err)
	}

	return p.LoadFromBytes(data)
}

// LoadFromBytes loads decoder definitions from XML bytes
func (p *DecoderParser) LoadFromBytes(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var config DecodersConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parse decoder XML: %w", err)
	}

	config.loadedAt = time.Now()
	config.fieldsMap = make(map[string]*Field)

	// Build fields map for quick lookup
	for i := range config.Groups {
		for j := range config.Groups[i].Fields {
			field := &config.Groups[i].Fields[j]
			config.fieldsMap[field.Name] = field

			// Parse alternative names
			if field.Alternatives != "" {
				field.altNames = strings.Split(field.Alternatives, ",")
				for _, alt := range field.altNames {
					alt = strings.TrimSpace(alt)
					if alt != "" {
						config.fieldsMap[alt] = field
					}
				}
			}
		}
	}

	p.config = &config
	p.compiled = false

	return nil
}

// Compile compiles all regex patterns for performance
func (p *DecoderParser) Compile() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.config == nil {
		return fmt.Errorf("no decoder config loaded")
	}

	if p.compiled {
		return nil
	}

	// Compile prematch pattern
	if p.config.Prematch.Pattern != "" {
		re, err := regexp.Compile(p.config.Prematch.Pattern)
		if err != nil {
			return fmt.Errorf("compile prematch pattern: %w", err)
		}
		p.config.Prematch.compiled = re
	}

	// Compile field patterns
	for i := range p.config.Groups {
		for j := range p.config.Groups[i].Fields {
			field := &p.config.Groups[i].Fields[j]
			if field.Regex != "" {
				re, err := regexp.Compile(field.Regex)
				if err != nil {
					return fmt.Errorf("compile field %s regex: %w", field.Name, err)
				}
				field.compiled = re
			}
		}
	}

	p.compiled = true
	return nil
}

// IsSophosLog checks if a log line matches the Sophos XGS format
func (p *DecoderParser) IsSophosLog(log string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil || p.config.Prematch.compiled == nil {
		return false
	}

	return p.config.Prematch.compiled.MatchString(log)
}

// ParseLog parses a Sophos XGS log line into structured fields
func (p *DecoderParser) ParseLog(log string) (*ParsedLog, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil, fmt.Errorf("no decoder config loaded")
	}

	if !p.compiled {
		return nil, fmt.Errorf("decoder not compiled, call Compile() first")
	}

	result := &ParsedLog{
		Fields: make(map[string]string),
		RawLog: log,
	}

	// Extract all fields using compiled regex
	for _, group := range p.config.Groups {
		for _, field := range group.Fields {
			if field.compiled == nil {
				continue
			}

			matches := field.compiled.FindStringSubmatch(log)
			if len(matches) > 1 {
				value := matches[1]

				// Apply normalization
				value = p.normalizeValue(value, &field)

				// Store with canonical field name
				result.Fields[field.Name] = value

				// Apply VX mapping if defined
				if field.VXMapping != "" {
					result.Fields[field.VXMapping] = value
				}
			} else if field.Default != "" {
				result.Fields[field.Name] = field.Default
			}
		}
	}

	// Extract timestamp if available
	if ts, ok := result.Fields["timestamp"]; ok {
		if t, err := time.Parse("2006-01-02T15:04:05-0700", ts); err == nil {
			result.Timestamp = t
		}
	}

	// Extract log type
	if lt, ok := result.Fields["log_type"]; ok {
		result.LogType = lt
	}

	return result, nil
}

// normalizeValue applies normalization rules to a field value
func (p *DecoderParser) normalizeValue(value string, field *Field) string {
	switch field.Normalization {
	case "uppercase":
		return strings.ToUpper(value)
	case "lowercase":
		return strings.ToLower(value)
	}

	// Apply allowed values validation
	if len(field.AllowedValues) > 0 {
		for _, allowed := range field.AllowedValues {
			if strings.EqualFold(value, allowed) {
				return allowed // Return canonical form
			}
		}
	}

	return value
}

// ValidateField validates a field value against its definition
func (p *DecoderParser) ValidateField(name, value string) *FieldValidationResult {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := &FieldValidationResult{
		Field: name,
		Value: value,
		Valid: true,
	}

	if p.config == nil {
		result.Valid = false
		result.Error = "no decoder config loaded"
		return result
	}

	field, ok := p.config.fieldsMap[name]
	if !ok {
		result.Warning = "unknown field"
		return result
	}

	// Check validation regex
	if field.Validation != "" {
		re, err := regexp.Compile(field.Validation)
		if err == nil && !re.MatchString(value) {
			result.Valid = false
			result.Error = fmt.Sprintf("value does not match validation pattern: %s", field.Validation)
		}
	}

	// Check allowed values
	if len(field.AllowedValues) > 0 {
		found := false
		for _, allowed := range field.AllowedValues {
			if strings.EqualFold(value, allowed) {
				found = true
				break
			}
		}
		if !found {
			result.Warning = fmt.Sprintf("value '%s' not in allowed values", value)
		}
	}

	// Check compliance
	if field.Compliance != nil && field.Compliance.Deprecated != "" {
		deprecated := strings.Split(field.Compliance.Deprecated, ",")
		for _, d := range deprecated {
			if strings.TrimSpace(d) == value {
				result.Warning = fmt.Sprintf("value '%s' is deprecated", value)
				break
			}
		}
	}

	return result
}

// GetField returns a field definition by name
func (p *DecoderParser) GetField(name string) *Field {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	return p.config.fieldsMap[name]
}

// GetAllFields returns all field definitions
func (p *DecoderParser) GetAllFields() []Field {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	var fields []Field
	for _, group := range p.config.Groups {
		fields = append(fields, group.Fields...)
	}
	return fields
}

// GetFieldGroups returns all field groups
func (p *DecoderParser) GetFieldGroups() []FieldGroup {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	return p.config.Groups
}

// GetRequiredFields returns all required fields
func (p *DecoderParser) GetRequiredFields() []Field {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	var required []Field
	for _, group := range p.config.Groups {
		for _, field := range group.Fields {
			if field.Required {
				required = append(required, field)
			}
		}
	}
	return required
}

// GetFieldsByType returns fields filtered by type
func (p *DecoderParser) GetFieldsByType(fieldType string) []Field {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	var filtered []Field
	for _, group := range p.config.Groups {
		for _, field := range group.Fields {
			if field.Type == fieldType {
				filtered = append(filtered, field)
			}
		}
	}
	return filtered
}

// GetMetadata returns decoder metadata
func (p *DecoderParser) GetMetadata() *DecoderMetadata {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	return &p.config.Metadata
}

// GetVersion returns the decoder version
func (p *DecoderParser) GetVersion() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return ""
	}

	return p.config.Version
}

// GetStats returns parser statistics
func (p *DecoderParser) GetStats() *ParserStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := &ParserStats{}

	if p.config != nil {
		stats.TotalGroupsLoaded = len(p.config.Groups)
		stats.DecodersLoadedAt = p.config.loadedAt

		for _, group := range p.config.Groups {
			stats.TotalFieldsLoaded += len(group.Fields)
		}
	}

	return stats
}

// GenerateClickHouseSchema generates ClickHouse column definitions
func (p *DecoderParser) GenerateClickHouseSchema() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	var columns []string
	for _, group := range p.config.Groups {
		for _, field := range group.Fields {
			if field.ClickHouseType == "" {
				continue
			}

			col := fmt.Sprintf("    %s %s", field.Name, field.ClickHouseType)
			if field.Description != "" {
				col += fmt.Sprintf(" COMMENT '%s'", strings.ReplaceAll(field.Description, "'", "''"))
			}
			columns = append(columns, col)
		}
	}

	return columns
}

// GenerateKVPExtractionVRL generates Vector VRL code for KVP extraction
func (p *DecoderParser) GenerateKVPExtractionVRL() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return ""
	}

	var vrl strings.Builder
	vrl.WriteString("# Auto-generated by VigilanceX Sophos Parser\n")
	vrl.WriteString("# Version: " + p.config.Version + "\n\n")

	// Group fields by priority
	for _, group := range p.config.Groups {
		vrl.WriteString(fmt.Sprintf("# === %s ===\n", strings.ToUpper(group.Name)))

		for _, field := range group.Fields {
			// Primary field extraction
			vrl.WriteString(fmt.Sprintf(".%s = get(.parsed, \"%s\")", field.Name, field.Name))

			// Add alternatives
			if len(field.altNames) > 0 {
				for _, alt := range field.altNames {
					vrl.WriteString(fmt.Sprintf(" ?? get(.parsed, \"%s\")", strings.TrimSpace(alt)))
				}
			}

			// Add default
			if field.Default != "" {
				vrl.WriteString(fmt.Sprintf(" ?? \"%s\"", field.Default))
			} else {
				vrl.WriteString(" ?? \"\"")
			}

			vrl.WriteString("\n")

			// Add normalization
			if field.Normalization == "uppercase" {
				vrl.WriteString(fmt.Sprintf(".%s = upcase(.%s)\n", field.Name, field.Name))
			} else if field.Normalization == "lowercase" {
				vrl.WriteString(fmt.Sprintf(".%s = downcase(.%s)\n", field.Name, field.Name))
			}
		}
		vrl.WriteString("\n")
	}

	return vrl.String()
}
