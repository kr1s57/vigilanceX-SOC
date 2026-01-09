package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/kr1s57/vigilancex/internal/adapter/parser/sophos"
)

// ParserHandler handles Sophos parser API endpoints
type ParserHandler struct {
	parser *sophos.Parser
}

// NewParserHandler creates a new parser handler
func NewParserHandler(parser *sophos.Parser) *ParserHandler {
	return &ParserHandler{parser: parser}
}

// GetStats returns parser statistics
// GET /api/v1/parser/stats
func (h *ParserHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	if h.parser == nil {
		JSONResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error":  "Parser not initialized",
			"loaded": false,
		})
		return
	}

	stats := h.parser.GetStats()
	mitreCoverage := h.parser.GetMitreCoverage()

	response := map[string]interface{}{
		"loaded":                h.parser.IsLoaded(),
		"version":               h.parser.Decoders.GetVersion(),
		"total_fields":          stats.TotalFieldsLoaded,
		"total_rules":           stats.TotalRulesLoaded,
		"total_groups":          stats.TotalGroupsLoaded,
		"mitre_techniques":      len(mitreCoverage),
		"decoders_loaded_at":    stats.DecodersLoadedAt,
		"rules_loaded_at":       stats.RulesLoadedAt,
		"total_logs_parsed":     stats.TotalLogsParsed,
		"total_rules_triggered": stats.TotalRulesTriggered,
	}

	JSONResponse(w, http.StatusOK, response)
}

// GetFields returns all field definitions
// GET /api/v1/parser/fields
func (h *ParserHandler) GetFields(w http.ResponseWriter, r *http.Request) {
	if h.parser == nil || !h.parser.IsLoaded() {
		JSONResponse(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Parser not loaded",
		})
		return
	}

	groups := h.parser.Decoders.GetFieldGroups()

	// Transform to simplified format
	result := make([]map[string]interface{}, 0)
	for _, group := range groups {
		groupData := map[string]interface{}{
			"name":        group.Name,
			"priority":    group.Priority,
			"description": group.Description,
			"fields":      make([]map[string]interface{}, 0),
		}

		for _, field := range group.Fields {
			fieldData := map[string]interface{}{
				"name":            field.Name,
				"type":            field.Type,
				"required":        field.Required,
				"clickhouse_type": field.ClickHouseType,
				"description":     field.Description,
			}
			if field.Example != "" {
				fieldData["example"] = field.Example
			}
			if len(field.AllowedValues) > 0 {
				fieldData["allowed_values"] = field.AllowedValues
			}
			groupData["fields"] = append(groupData["fields"].([]map[string]interface{}), fieldData)
		}

		result = append(result, groupData)
	}

	JSONResponse(w, http.StatusOK, result)
}

// GetRules returns all rule definitions
// GET /api/v1/parser/rules
func (h *ParserHandler) GetRules(w http.ResponseWriter, r *http.Request) {
	if h.parser == nil || !h.parser.IsLoaded() {
		JSONResponse(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Parser not loaded",
		})
		return
	}

	groups := h.parser.Rules.GetAllRuleGroups()

	// Transform to simplified format
	result := make([]map[string]interface{}, 0)
	for _, group := range groups {
		groupData := map[string]interface{}{
			"name":        group.Name,
			"id_range":    group.IDRange,
			"description": group.Description,
			"rules":       make([]map[string]interface{}, 0),
		}

		for _, rule := range group.Rules {
			ruleData := map[string]interface{}{
				"id":          rule.ID,
				"level":       rule.Level,
				"description": rule.Description,
				"category":    rule.VXCategory,
			}
			if rule.Mitre != nil && len(rule.Mitre.Techniques) > 0 {
				techniques := make([]string, 0)
				for _, t := range rule.Mitre.Techniques {
					techniques = append(techniques, t.ID)
				}
				ruleData["mitre"] = techniques
			}
			if rule.VXAction != nil {
				ruleData["action"] = map[string]interface{}{
					"types":    rule.VXAction.Types,
					"severity": rule.VXAction.Severity,
					"duration": rule.VXAction.Duration,
				}
			}
			groupData["rules"] = append(groupData["rules"].([]map[string]interface{}), ruleData)
		}

		result = append(result, groupData)
	}

	JSONResponse(w, http.StatusOK, result)
}

// GetMitreCoverage returns MITRE ATT&CK coverage
// GET /api/v1/parser/mitre
func (h *ParserHandler) GetMitreCoverage(w http.ResponseWriter, r *http.Request) {
	if h.parser == nil || !h.parser.IsLoaded() {
		JSONResponse(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Parser not loaded",
		})
		return
	}

	coverage := h.parser.GetMitreCoverage()

	result := make([]map[string]interface{}, 0)
	for techID, count := range coverage {
		result = append(result, map[string]interface{}{
			"technique": techID,
			"rules":     count,
		})
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"total_techniques": len(coverage),
		"coverage":         result,
	})
}

// TestParse tests parsing a log line
// POST /api/v1/parser/test
func (h *ParserHandler) TestParse(w http.ResponseWriter, r *http.Request) {
	if h.parser == nil || !h.parser.IsLoaded() {
		JSONResponse(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Parser not loaded",
		})
		return
	}

	var req struct {
		Log string `json:"log"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
		return
	}

	if req.Log == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{
			"error": "Log field is required",
		})
		return
	}

	parsed, triggered, err := h.parser.ParseAndEvaluate(req.Log)
	if err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Transform triggered rules
	triggeredData := make([]map[string]interface{}, 0)
	for _, tr := range triggered {
		data := map[string]interface{}{
			"rule_id":     tr.RuleID,
			"level":       tr.Level,
			"description": tr.Description,
			"category":    tr.Category,
		}
		if len(tr.Mitre) > 0 {
			data["mitre"] = tr.Mitre
		}
		if tr.Action != nil {
			data["action"] = tr.Action.Types
			data["severity"] = tr.Action.Severity
		}
		triggeredData = append(triggeredData, data)
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"parsed": map[string]interface{}{
			"log_type":  parsed.LogType,
			"timestamp": parsed.Timestamp,
			"fields":    parsed.Fields,
		},
		"triggered_rules": triggeredData,
		"rules_count":     len(triggered),
	})
}
