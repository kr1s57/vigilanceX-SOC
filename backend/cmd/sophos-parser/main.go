// sophos-parser is a CLI tool for managing Sophos XGS log definitions.
// It can load, validate, and generate configurations from XML definitions.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kr1s57/vigilancex/internal/adapter/parser/sophos"
)

const version = "1.0.0"

func main() {
	// Define flags
	decodersPath := flag.String("decoders", "", "Path to vigilanceX_XGS_decoders.xml")
	rulesPath := flag.String("rules", "", "Path to vigilanceX_XGS_rules.xml")
	scenariosDir := flag.String("scenarios-dir", "", "Directory containing XML files (alternative to individual paths)")

	// Commands
	showStats := flag.Bool("stats", false, "Show parser statistics")
	showFields := flag.Bool("fields", false, "List all field definitions")
	showRules := flag.Bool("rules-list", false, "List all rule definitions")
	showMitre := flag.Bool("mitre", false, "Show MITRE ATT&CK coverage")
	generateVector := flag.Bool("gen-vector", false, "Generate Vector.toml configuration")
	generateYAML := flag.Bool("gen-yaml", false, "Generate Detect2Ban YAML scenarios")
	testLog := flag.String("test", "", "Test parsing a log line")
	outputFile := flag.String("output", "", "Output file (default: stdout)")
	minLevel := flag.Int("min-level", 5, "Minimum rule level for YAML generation")
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	showVersion := flag.Bool("version", false, "Show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "VIGILANCE X - Sophos XGS Parser CLI v%s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -scenarios-dir ./scenarios -stats\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -decoders ./decoders.xml -rules ./rules.xml -gen-vector -output vector.toml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -scenarios-dir ./scenarios -test 'device_name=\"XGS\" timestamp=\"...\"'\n", os.Args[0])
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("sophos-parser v%s\n", version)
		os.Exit(0)
	}

	// Determine paths
	if *scenariosDir != "" {
		if *decodersPath == "" {
			*decodersPath = filepath.Join(*scenariosDir, "vigilanceX_XGS_decoders.xml")
		}
		if *rulesPath == "" {
			*rulesPath = filepath.Join(*scenariosDir, "vigilanceX_XGS_rules.xml")
		}
	}

	// Validate paths
	if *decodersPath == "" || *rulesPath == "" {
		fmt.Fprintln(os.Stderr, "Error: Must specify -scenarios-dir or both -decoders and -rules")
		flag.Usage()
		os.Exit(1)
	}

	// Load parser
	parser := sophos.New()

	fmt.Fprintf(os.Stderr, "Loading decoders from: %s\n", *decodersPath)
	fmt.Fprintf(os.Stderr, "Loading rules from: %s\n", *rulesPath)

	if err := parser.Load(sophos.Config{
		DecodersPath: *decodersPath,
		RulesPath:    *rulesPath,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading parser: %v\n", err)
		os.Exit(1)
	}

	// Setup output
	var output = os.Stdout
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		output = f
	}

	// Execute command
	switch {
	case *showStats:
		stats := parser.GetStats()
		if *jsonOutput {
			enc := json.NewEncoder(output)
			enc.SetIndent("", "  ")
			enc.Encode(stats)
		} else {
			fmt.Fprintf(output, "VIGILANCE X - Sophos Parser Statistics\n")
			fmt.Fprintf(output, "========================================\n\n")
			fmt.Fprintf(output, "Decoders:\n")
			fmt.Fprintf(output, "  Total Fields: %d\n", stats.TotalFieldsLoaded)
			fmt.Fprintf(output, "  Total Groups: %d\n", stats.TotalGroupsLoaded)
			fmt.Fprintf(output, "  Loaded At: %s\n\n", stats.DecodersLoadedAt.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(output, "Rules:\n")
			fmt.Fprintf(output, "  Total Rules: %d\n", stats.TotalRulesLoaded)
			fmt.Fprintf(output, "  Loaded At: %s\n\n", stats.RulesLoadedAt.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(output, "Performance:\n")
			fmt.Fprintf(output, "  Load Time: %v\n", stats.LastParseTime)
		}

	case *showFields:
		fields := parser.Decoders.GetAllFields()
		if *jsonOutput {
			enc := json.NewEncoder(output)
			enc.SetIndent("", "  ")
			enc.Encode(fields)
		} else {
			fmt.Fprintf(output, "FIELD NAME                    TYPE        REQUIRED  CLICKHOUSE TYPE\n")
			fmt.Fprintf(output, "%-30s %-11s %-9s %s\n", strings.Repeat("-", 30), strings.Repeat("-", 11), strings.Repeat("-", 9), strings.Repeat("-", 20))
			for _, f := range fields {
				req := "no"
				if f.Required {
					req = "yes"
				}
				fmt.Fprintf(output, "%-30s %-11s %-9s %s\n", f.Name, f.Type, req, f.ClickHouseType)
			}
			fmt.Fprintf(output, "\nTotal: %d fields\n", len(fields))
		}

	case *showRules:
		groups := parser.Rules.GetAllRuleGroups()
		if *jsonOutput {
			enc := json.NewEncoder(output)
			enc.SetIndent("", "  ")
			enc.Encode(groups)
		} else {
			for _, g := range groups {
				fmt.Fprintf(output, "\n=== %s (%s) ===\n", strings.ToUpper(g.Name), g.IDRange)
				fmt.Fprintf(output, "%s\n\n", g.Description)
				fmt.Fprintf(output, "RULE ID   LEVEL  CATEGORY                       DESCRIPTION\n")
				fmt.Fprintf(output, "%-9s %-6s %-30s %s\n", strings.Repeat("-", 9), strings.Repeat("-", 6), strings.Repeat("-", 30), strings.Repeat("-", 40))
				for _, r := range g.Rules {
					cat := r.VXCategory
					if cat == "" {
						cat = "-"
					}
					desc := r.Description
					if len(desc) > 40 {
						desc = desc[:37] + "..."
					}
					fmt.Fprintf(output, "%-9s %-6d %-30s %s\n", r.ID, r.Level, cat, desc)
				}
			}
		}

	case *showMitre:
		coverage := parser.GetMitreCoverage()
		if *jsonOutput {
			enc := json.NewEncoder(output)
			enc.SetIndent("", "  ")
			enc.Encode(coverage)
		} else {
			fmt.Fprintf(output, "MITRE ATT&CK Coverage\n")
			fmt.Fprintf(output, "=====================\n\n")
			fmt.Fprintf(output, "TECHNIQUE    RULES\n")
			fmt.Fprintf(output, "%-12s %s\n", strings.Repeat("-", 12), strings.Repeat("-", 5))
			total := 0
			for tech, count := range coverage {
				fmt.Fprintf(output, "%-12s %d\n", tech, count)
				total++
			}
			fmt.Fprintf(output, "\nTotal techniques covered: %d\n", total)
		}

	case *generateVector:
		config := parser.GenerateVectorConfig()
		fmt.Fprint(output, config)
		if *outputFile != "" {
			fmt.Fprintf(os.Stderr, "Vector configuration written to: %s\n", *outputFile)
		}

	case *generateYAML:
		scenarios := parser.ExportDetect2BanScenarios(*minLevel)
		if len(scenarios) == 0 {
			fmt.Fprintln(os.Stderr, "No scenarios generated (check min-level)")
			os.Exit(0)
		}

		if *outputFile != "" {
			// Write to directory
			dir := *outputFile
			if err := os.MkdirAll(dir, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
				os.Exit(1)
			}
			for name, content := range scenarios {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", path, err)
					continue
				}
				fmt.Fprintf(os.Stderr, "Written: %s\n", path)
			}
		} else {
			// Print to stdout
			for name, content := range scenarios {
				fmt.Fprintf(output, "# === %s ===\n%s\n\n", name, content)
			}
		}

	case *testLog != "":
		parsed, triggered, err := parser.ParseAndEvaluate(*testLog)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing log: %v\n", err)
			os.Exit(1)
		}

		if *jsonOutput {
			result := map[string]interface{}{
				"parsed":    parsed,
				"triggered": triggered,
			}
			enc := json.NewEncoder(output)
			enc.SetIndent("", "  ")
			enc.Encode(result)
		} else {
			fmt.Fprintf(output, "PARSED LOG\n")
			fmt.Fprintf(output, "==========\n")
			fmt.Fprintf(output, "Log Type: %s\n", parsed.LogType)
			fmt.Fprintf(output, "Timestamp: %s\n\n", parsed.Timestamp.Format("2006-01-02 15:04:05"))

			fmt.Fprintf(output, "EXTRACTED FIELDS:\n")
			for k, v := range parsed.Fields {
				if v != "" {
					fmt.Fprintf(output, "  %s = %s\n", k, v)
				}
			}

			fmt.Fprintf(output, "\nTRIGGERED RULES: %d\n", len(triggered))
			for _, tr := range triggered {
				fmt.Fprintf(output, "  [%s] Level %d: %s\n", tr.RuleID, tr.Level, tr.Description)
				if tr.Category != "" {
					fmt.Fprintf(output, "    Category: %s\n", tr.Category)
				}
				if len(tr.Mitre) > 0 {
					fmt.Fprintf(output, "    MITRE: %s\n", strings.Join(tr.Mitre, ", "))
				}
				if tr.Action != nil {
					fmt.Fprintf(output, "    Action: %v (severity: %s)\n", tr.Action.Types, tr.Action.Severity)
				}
			}
		}

	default:
		fmt.Fprintln(os.Stderr, "No command specified. Use -h for help.")
		flag.Usage()
		os.Exit(1)
	}
}
