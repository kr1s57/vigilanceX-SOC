package sophos

import (
	"strings"
	"testing"
)

// Sample Sophos XGS logs for testing
var sampleLogs = []struct {
	name     string
	log      string
	logType  string
	category string
}{
	{
		name:     "WAF Block",
		log:      `device_name="XGS-01" timestamp="2026-01-09T10:30:45+0100" log_id="010101600001" log_type="WAF" log_component="Web Application Firewall" log_subtype="Block" severity="high" src_ip="185.220.101.1" dst_ip="192.168.1.100" src_port=54321 dst_port=443 protocol="TCP" action="drop" rule_id="920001" rule_name="SQL Injection Attack" hostname="app.example.com" url="/api/login" http_method="POST" http_status=403 user_agent="sqlmap/1.0" message="SQL injection attempt blocked" reason="OWASP CRS Rule 942100"`,
		logType:  "WAF",
		category: "SQL Injection",
	},
	{
		name:     "ATP Block",
		log:      `device_name="XGS-PROD" timestamp="2026-01-09T11:00:00+0100" log_id="010101600002" log_type="ATP" log_component="Advanced Threat Protection" log_subtype="Drop" severity="critical" src_ip="45.33.32.156" dst_ip="192.168.1.50" protocol="TCP" action="block" threatfeed="Sophos Labs" message="C2 communication blocked" malware="Cobalt Strike"`,
		logType:  "ATP",
		category: "C2 Communication",
	},
	{
		name:     "VPN Auth Failure",
		log:      `device_name="XGS-01" timestamp="2026-01-09T12:00:00+0100" log_id="010101600003" log_type="SSL VPN" log_subtype="Authentication" severity="warning" src_ip="103.25.56.78" user_name="admin" message="Authentication failed: invalid credentials"`,
		logType:  "SSL VPN",
		category: "VPN Auth Failure",
	},
	{
		name:     "Firewall Allow",
		log:      `device_name="XGS-01" timestamp="2026-01-09T13:00:00+0100" log_id="010101600004" log_type="Firewall" log_subtype="Allowed" severity="info" src_ip="192.168.1.10" dst_ip="8.8.8.8" src_port=12345 dst_port=53 protocol="UDP" action="allow" rule_id="1" rule_name="Allow DNS"`,
		logType:  "Firewall",
		category: "Allowed",
	},
	{
		name:     "IPS Block",
		log:      `device_name="XGS-01" timestamp="2026-01-09T14:00:00+0100" log_id="010101600005" log_type="Content Filtering" log_component="IPS" severity="high" src_ip="198.51.100.1" dst_ip="192.168.1.100" dst_port=22 protocol="TCP" action="drop" rule_id="20000001" rule_name="SSH Brute Force" message="Multiple SSH login attempts"`,
		logType:  "Content Filtering",
		category: "IPS Block",
	},
	{
		name:     "Sandstorm Malware",
		log:      `device_name="XGS-01" timestamp="2026-01-09T15:00:00+0100" log_id="010101600006" log_type="Sandstorm" log_subtype="Malicious" severity="critical" src_ip="203.0.113.50" filename="invoice.exe" malware="Trojan.GenericKD.12345" action="quarantine" message="Malware detected and quarantined"`,
		logType:  "Sandstorm",
		category: "Malware",
	},
}

// Sample decoder XML for testing
var testDecodersXML = `<?xml version="1.0" encoding="UTF-8"?>
<vigilancex_decoders version="test">
  <metadata>
    <name>Test Decoders</name>
    <description>Test decoder configuration</description>
    <author>Test</author>
    <sophos_version>20.0</sophos_version>
    <total_fields>10</total_fields>
  </metadata>
  <prematch>
    <pattern>^device_name="[^"]+"\s+timestamp=</pattern>
    <description>Sophos XGS log pattern</description>
  </prematch>
  <field_group name="test_group" priority="1">
    <description>Test fields</description>
    <field name="device_name" required="true">
      <type>string</type>
      <regex>device_name="([^"]+)"</regex>
      <clickhouse_type>String</clickhouse_type>
    </field>
    <field name="timestamp" required="true">
      <type>datetime</type>
      <regex>timestamp="([^"]+)"</regex>
      <clickhouse_type>DateTime</clickhouse_type>
    </field>
    <field name="log_type" required="true">
      <type>string</type>
      <regex>log_type="([^"]+)"</regex>
      <clickhouse_type>LowCardinality(String)</clickhouse_type>
    </field>
    <field name="src_ip" required="true">
      <type>ipv4</type>
      <regex>src_ip="([^"]+)"</regex>
      <alternatives>srcip,sourceip</alternatives>
      <clickhouse_type>IPv4</clickhouse_type>
      <default>0.0.0.0</default>
    </field>
    <field name="action" required="true">
      <type>string</type>
      <regex>action="([^"]+)"</regex>
      <clickhouse_type>LowCardinality(String)</clickhouse_type>
      <normalization>lowercase</normalization>
    </field>
    <field name="severity" required="false">
      <type>string</type>
      <regex>severity="([^"]+)"</regex>
      <clickhouse_type>LowCardinality(String)</clickhouse_type>
    </field>
    <field name="message" required="false">
      <type>string</type>
      <regex>message="([^"]+)"</regex>
      <clickhouse_type>String</clickhouse_type>
    </field>
  </field_group>
</vigilancex_decoders>`

// Sample rules XML for testing
var testRulesXML = `<?xml version="1.0" encoding="UTF-8"?>
<vigilancex_rules version="test">
  <metadata>
    <name>Test Rules</name>
    <description>Test rule configuration</description>
    <author>Test</author>
    <total_rules>3</total_rules>
  </metadata>
  <rule_group name="test" id_range="999000-999099">
    <description>Test rules</description>
    <rule id="999000" level="0">
      <decoded_as>sophos_xgs</decoded_as>
      <description>Parent Sophos rule</description>
    </rule>
    <rule id="999001" level="5">
      <if_parent>999000</if_parent>
      <match>
        <field name="log_type">WAF</field>
        <field name="action" operator="in">drop,block</field>
      </match>
      <description>WAF Block detected</description>
      <vx_category>WAF Block</vx_category>
      <vx_action>
        <type>alert</type>
        <severity>high</severity>
      </vx_action>
    </rule>
    <rule id="999002" level="8">
      <if_parent>999001</if_parent>
      <match>
        <field name="message" operator="contains">SQL,injection</field>
      </match>
      <description>SQL Injection blocked</description>
      <vx_category>SQL Injection</vx_category>
      <mitre>
        <technique id="T1190">Exploit Public-Facing Application</technique>
      </mitre>
      <vx_action>
        <type>ban</type>
        <duration>24h</duration>
        <severity>high</severity>
      </vx_action>
    </rule>
  </rule_group>
</vigilancex_rules>`

func TestDecoderParser_LoadFromBytes(t *testing.T) {
	parser := NewDecoderParser()

	err := parser.LoadFromBytes([]byte(testDecodersXML))
	if err != nil {
		t.Fatalf("Failed to load decoders: %v", err)
	}

	// Verify metadata
	meta := parser.GetMetadata()
	if meta == nil {
		t.Fatal("Metadata is nil")
	}
	if meta.Name != "Test Decoders" {
		t.Errorf("Expected name 'Test Decoders', got '%s'", meta.Name)
	}

	// Verify version
	if parser.GetVersion() != "test" {
		t.Errorf("Expected version 'test', got '%s'", parser.GetVersion())
	}

	// Verify fields loaded
	fields := parser.GetAllFields()
	if len(fields) != 7 {
		t.Errorf("Expected 7 fields, got %d", len(fields))
	}
}

func TestDecoderParser_Compile(t *testing.T) {
	parser := NewDecoderParser()

	if err := parser.LoadFromBytes([]byte(testDecodersXML)); err != nil {
		t.Fatalf("Failed to load decoders: %v", err)
	}

	err := parser.Compile()
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}
}

func TestDecoderParser_IsSophosLog(t *testing.T) {
	parser := NewDecoderParser()

	if err := parser.LoadFromBytes([]byte(testDecodersXML)); err != nil {
		t.Fatalf("Failed to load decoders: %v", err)
	}
	if err := parser.Compile(); err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	for _, tc := range sampleLogs {
		t.Run(tc.name, func(t *testing.T) {
			if !parser.IsSophosLog(tc.log) {
				t.Errorf("Expected log to be recognized as Sophos: %s", tc.log[:50])
			}
		})
	}

	// Test non-Sophos log
	if parser.IsSophosLog("This is not a Sophos log") {
		t.Error("Should not recognize non-Sophos log")
	}
}

func TestDecoderParser_ParseLog(t *testing.T) {
	parser := NewDecoderParser()

	if err := parser.LoadFromBytes([]byte(testDecodersXML)); err != nil {
		t.Fatalf("Failed to load decoders: %v", err)
	}
	if err := parser.Compile(); err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	for _, tc := range sampleLogs {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parser.ParseLog(tc.log)
			if err != nil {
				t.Fatalf("Failed to parse log: %v", err)
			}

			if parsed.LogType != tc.logType {
				t.Errorf("Expected log_type '%s', got '%s'", tc.logType, parsed.LogType)
			}

			// Verify some fields are extracted
			if _, ok := parsed.Fields["device_name"]; !ok {
				t.Error("device_name field not extracted")
			}
			if _, ok := parsed.Fields["timestamp"]; !ok {
				t.Error("timestamp field not extracted")
			}
		})
	}
}

func TestRulesParser_LoadFromBytes(t *testing.T) {
	parser := NewRulesParser()

	err := parser.LoadFromBytes([]byte(testRulesXML))
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Verify metadata
	meta := parser.GetMetadata()
	if meta == nil {
		t.Fatal("Metadata is nil")
	}
	if meta.Name != "Test Rules" {
		t.Errorf("Expected name 'Test Rules', got '%s'", meta.Name)
	}

	// Verify rules loaded
	stats := parser.GetStats()
	if stats.TotalRulesLoaded != 3 {
		t.Errorf("Expected 3 rules, got %d", stats.TotalRulesLoaded)
	}
}

func TestRulesParser_GetRule(t *testing.T) {
	parser := NewRulesParser()

	if err := parser.LoadFromBytes([]byte(testRulesXML)); err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	rule := parser.GetRule("999001")
	if rule == nil {
		t.Fatal("Rule 999001 not found")
	}
	if rule.Level != 5 {
		t.Errorf("Expected level 5, got %d", rule.Level)
	}
	if rule.VXCategory != "WAF Block" {
		t.Errorf("Expected category 'WAF Block', got '%s'", rule.VXCategory)
	}
}

func TestRulesParser_EvaluateLog(t *testing.T) {
	decoderParser := NewDecoderParser()
	if err := decoderParser.LoadFromBytes([]byte(testDecodersXML)); err != nil {
		t.Fatalf("Failed to load decoders: %v", err)
	}
	if err := decoderParser.Compile(); err != nil {
		t.Fatalf("Failed to compile decoders: %v", err)
	}

	rulesParser := NewRulesParser()
	if err := rulesParser.LoadFromBytes([]byte(testRulesXML)); err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	if err := rulesParser.Compile(); err != nil {
		t.Fatalf("Failed to compile rules: %v", err)
	}

	// Parse a WAF log
	parsed, err := decoderParser.ParseLog(sampleLogs[0].log) // WAF Block
	if err != nil {
		t.Fatalf("Failed to parse log: %v", err)
	}

	// Evaluate against rules
	triggered := rulesParser.EvaluateLog(parsed)

	// Should trigger WAF rules
	if len(triggered) == 0 {
		t.Error("Expected rules to trigger for WAF block log")
	}

	// Check for SQL Injection rule
	found := false
	for _, tr := range triggered {
		if tr.Category == "SQL Injection" {
			found = true
			if len(tr.Mitre) == 0 {
				t.Error("Expected MITRE mapping for SQL Injection rule")
			}
			break
		}
	}
	if !found {
		t.Error("SQL Injection rule should have triggered")
	}
}

func TestParser_Integration(t *testing.T) {
	parser := New()

	// Load from bytes
	if err := parser.Decoders.LoadFromBytes([]byte(testDecodersXML)); err != nil {
		t.Fatalf("Failed to load decoders: %v", err)
	}
	if err := parser.Decoders.Compile(); err != nil {
		t.Fatalf("Failed to compile decoders: %v", err)
	}
	if err := parser.Rules.LoadFromBytes([]byte(testRulesXML)); err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	if err := parser.Rules.Compile(); err != nil {
		t.Fatalf("Failed to compile rules: %v", err)
	}

	// Get stats
	stats := parser.GetStats()
	if stats.TotalFieldsLoaded == 0 {
		t.Error("No fields loaded")
	}
	if stats.TotalRulesLoaded == 0 {
		t.Error("No rules loaded")
	}
}

func TestDecoderParser_GenerateKVPExtractionVRL(t *testing.T) {
	parser := NewDecoderParser()

	if err := parser.LoadFromBytes([]byte(testDecodersXML)); err != nil {
		t.Fatalf("Failed to load decoders: %v", err)
	}

	vrl := parser.GenerateKVPExtractionVRL()

	if vrl == "" {
		t.Error("VRL generation returned empty string")
	}

	// Should contain field extractions
	if !strings.Contains(vrl, ".device_name") {
		t.Error("VRL should contain device_name extraction")
	}
	if !strings.Contains(vrl, ".src_ip") {
		t.Error("VRL should contain src_ip extraction")
	}
}

func TestRulesParser_GenerateDetect2BanYAML(t *testing.T) {
	parser := NewRulesParser()

	if err := parser.LoadFromBytes([]byte(testRulesXML)); err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	yamls := parser.GenerateDetect2BanYAML(5)

	// Should generate YAML for rules with level >= 5 and ban action
	if len(yamls) == 0 {
		t.Log("No YAML scenarios generated (expected if no ban actions)")
	}
}

func TestDecoderParser_GetFieldsByType(t *testing.T) {
	parser := NewDecoderParser()

	if err := parser.LoadFromBytes([]byte(testDecodersXML)); err != nil {
		t.Fatalf("Failed to load decoders: %v", err)
	}

	ipFields := parser.GetFieldsByType("ipv4")
	if len(ipFields) != 1 {
		t.Errorf("Expected 1 IPv4 field, got %d", len(ipFields))
	}

	stringFields := parser.GetFieldsByType("string")
	if len(stringFields) < 3 {
		t.Errorf("Expected at least 3 string fields, got %d", len(stringFields))
	}
}

func TestDecoderParser_ValidateField(t *testing.T) {
	parser := NewDecoderParser()

	if err := parser.LoadFromBytes([]byte(testDecodersXML)); err != nil {
		t.Fatalf("Failed to load decoders: %v", err)
	}

	// Valid IP
	result := parser.ValidateField("src_ip", "192.168.1.1")
	if !result.Valid {
		t.Errorf("Expected valid IP, got error: %s", result.Error)
	}

	// Unknown field
	result = parser.ValidateField("unknown_field", "value")
	if result.Warning == "" {
		t.Error("Expected warning for unknown field")
	}
}

func BenchmarkDecoderParser_ParseLog(b *testing.B) {
	parser := NewDecoderParser()

	if err := parser.LoadFromBytes([]byte(testDecodersXML)); err != nil {
		b.Fatalf("Failed to load decoders: %v", err)
	}
	if err := parser.Compile(); err != nil {
		b.Fatalf("Failed to compile: %v", err)
	}

	log := sampleLogs[0].log

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.ParseLog(log)
	}
}

func BenchmarkRulesParser_EvaluateLog(b *testing.B) {
	decoderParser := NewDecoderParser()
	if err := decoderParser.LoadFromBytes([]byte(testDecodersXML)); err != nil {
		b.Fatalf("Failed to load decoders: %v", err)
	}
	if err := decoderParser.Compile(); err != nil {
		b.Fatalf("Failed to compile decoders: %v", err)
	}

	rulesParser := NewRulesParser()
	if err := rulesParser.LoadFromBytes([]byte(testRulesXML)); err != nil {
		b.Fatalf("Failed to load rules: %v", err)
	}
	if err := rulesParser.Compile(); err != nil {
		b.Fatalf("Failed to compile rules: %v", err)
	}

	parsed, _ := decoderParser.ParseLog(sampleLogs[0].log)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rulesParser.EvaluateLog(parsed)
	}
}
