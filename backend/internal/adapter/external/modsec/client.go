package modsec

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// LogEntry represents a parsed ModSec log entry
type LogEntry struct {
	Timestamp time.Time
	SrcIP     string
	SrcPort   string
	RuleID    string
	Message   string
	Severity  string
	Hostname  string
	URI       string
	UniqueID  string
	RuleFile  string
	FullLog   string
	// New fields for detailed parsing
	RuleData      string   // Matched data
	CRSVersion    string   // e.g., "OWASP_CRS/3.3.3"
	ParanoiaLevel int      // 1-4
	AttackType    string   // sql, xss, lfi, rfi, rce, protocol
	Tags          []string // All tags
	IsBlocking    bool     // True if rule 949110 (blocking rule)
	TotalScore    int      // Anomaly score from blocking rule
}

// Client handles SSH connection to Sophos XGS for ModSec log retrieval
type Client struct {
	host    string
	port    int
	user    string
	keyPath string
	logPath string
	logger  *slog.Logger
}

// Config holds client configuration
type Config struct {
	Host    string
	Port    int
	User    string
	KeyPath string
	LogPath string
}

// NewClient creates a new ModSec SSH client
func NewClient(cfg Config, logger *slog.Logger) *Client {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.User == "" {
		cfg.User = "admin"
	}
	if cfg.LogPath == "" {
		cfg.LogPath = "/log/reverseproxy.log"
	}

	return &Client{
		host:    cfg.Host,
		port:    cfg.Port,
		user:    cfg.User,
		keyPath: cfg.KeyPath,
		logPath: cfg.LogPath,
		logger:  logger,
	}
}

// FetchModSecLogs fetches and parses ModSec logs from XGS
func (c *Client) FetchModSecLogs(ctx context.Context, since time.Time, limit int) ([]LogEntry, error) {
	if c.host == "" {
		return nil, fmt.Errorf("sophos SSH host not configured")
	}

	// Read SSH key
	key, err := os.ReadFile(c.keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: c.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	// Connect to SSH
	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH: %w", err)
	}
	defer client.Close()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Request PTY for interactive menu
	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		return nil, fmt.Errorf("failed to request PTY: %w", err)
	}

	// Set up stdin/stdout
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}
	var stdout bytes.Buffer
	session.Stdout = &stdout

	// Start shell
	if err := session.Shell(); err != nil {
		return nil, fmt.Errorf("failed to start shell: %w", err)
	}

	// Navigate menu and execute command
	// Menu: 5 (Device Management) -> 3 (Advanced Shell)
	if limit == 0 {
		limit = 500
	}
	// Use tail with limited output to prevent timeout
	cmd := fmt.Sprintf("tail -10000 %s 2>/dev/null | grep 'security2:error' | tail -%d; echo '===END_MODSEC==='", c.logPath, limit)

	// Wait for menu to appear, then send commands with delays
	time.Sleep(2 * time.Second)
	io.WriteString(stdin, "5\n")
	time.Sleep(500 * time.Millisecond)
	io.WriteString(stdin, "3\n")
	time.Sleep(1 * time.Second)
	io.WriteString(stdin, cmd+"\n")
	time.Sleep(500 * time.Millisecond)
	io.WriteString(stdin, "exit\n")
	time.Sleep(200 * time.Millisecond)
	io.WriteString(stdin, "exit\n")
	time.Sleep(100 * time.Millisecond)
	io.WriteString(stdin, "0\n") // Exit from Device Management menu
	stdin.Close()

	// Wait for marker string or timeout
	startTime := time.Now()
	timeout := 60 * time.Second
	marker := "===END_MODSEC==="

	for {
		if time.Since(startTime) > timeout {
			output := stdout.String()
			if strings.Contains(output, "[security2:error]") {
				// We have data, parse what we got
				c.logger.Info("SSH timeout but got data, parsing partial output", "length", len(output))
				return c.parseModSecLogs(output, since)
			}
			c.logger.Warn("SSH timeout - no usable data", "length", len(output))
			return nil, fmt.Errorf("SSH command timed out")
		}

		output := stdout.String()
		if strings.Contains(output, marker) {
			c.logger.Info("ModSec sync completed", "output_length", len(output))
			return c.parseModSecLogs(output, since)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// truncate returns the first n characters of a string
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// parseModSecLogs parses the raw log output into structured entries
func (c *Client) parseModSecLogs(output string, since time.Time) ([]LogEntry, error) {
	var entries []LogEntry

	// Debug: log output size
	c.logger.Debug("Raw output received", "total_length", len(output))

	// Regex patterns for ModSec log parsing
	// Example: [Tue Jan 06 15:31:05.952669 2026] [security2:error] [pid 14532:tid 140699437463296] [client 195.250.31.127:22167] ModSecurity: Warning...
	timestampRe := regexp.MustCompile(`\[(\w{3} \w{3} \s?\d{1,2} \d{2}:\d{2}:\d{2}\.\d+ \d{4})\]`)
	clientRe := regexp.MustCompile(`\[client (\d+\.\d+\.\d+\.\d+):(\d+)\]`)
	idRe := regexp.MustCompile(`\[id "(\d+)"\]`)
	msgRe := regexp.MustCompile(`\[msg "([^"]+)"\]`)
	severityRe := regexp.MustCompile(`\[severity "([^"]+)"\]`)
	hostnameRe := regexp.MustCompile(`\[hostname "([^"]+)"\]`)
	uriRe := regexp.MustCompile(`\[uri "([^"]+)"\]`)
	uniqueIDRe := regexp.MustCompile(`\[unique_id "([^"]+)"\]`)
	fileRe := regexp.MustCompile(`\[file "([^"]+)"\]`)
	// New regex patterns for detailed parsing
	dataRe := regexp.MustCompile(`\[data "([^"]+)"\]`)
	verRe := regexp.MustCompile(`\[ver "([^"]+)"\]`)
	tagRe := regexp.MustCompile(`\[tag "([^"]+)"\]`)
	paranoiaRe := regexp.MustCompile(`paranoia-level/(\d+)`)
	attackTypeRe := regexp.MustCompile(`attack-(\w+)`)
	totalScoreRe := regexp.MustCompile(`Total (?:Inbound )?Score: (\d+)`)

	lines := strings.Split(output, "\n")
	securityErrorCount := 0
	for _, line := range lines {
		if !strings.Contains(line, "[security2:error]") {
			continue
		}
		securityErrorCount++

		entry := LogEntry{FullLog: line}

		// Parse timestamp - handle both "Jan 06" and "Jan  6" formats
		if matches := timestampRe.FindStringSubmatch(line); len(matches) > 1 {
			// Normalize spaces in date string
			dateStr := strings.ReplaceAll(matches[1], "  ", " ")
			// XGS logs are in local time (CET for Luxembourg)
			loc, _ := time.LoadLocation("Europe/Luxembourg")
			if loc == nil {
				loc = time.UTC
			}
			// Try parsing with two-digit day first, then single digit
			var t time.Time
			var err error
			t, err = time.ParseInLocation("Mon Jan 2 15:04:05.000000 2006", dateStr, loc)
			if err != nil {
				t, err = time.ParseInLocation("Mon Jan 02 15:04:05.000000 2006", dateStr, loc)
			}
			if err == nil {
				entry.Timestamp = t
				// Note: We no longer filter by 'since' time here.
				// ReplacingMergeTree in ClickHouse handles deduplication,
				// so we can safely process all entries from SSH output.
			}
		}

		// Parse client IP and port
		if matches := clientRe.FindStringSubmatch(line); len(matches) > 2 {
			entry.SrcIP = matches[1]
			entry.SrcPort = matches[2]
		}

		// Parse rule ID
		if matches := idRe.FindStringSubmatch(line); len(matches) > 1 {
			entry.RuleID = matches[1]
			// Check if this is a blocking rule (949110, 949111, 959100)
			if entry.RuleID == "949110" || entry.RuleID == "949111" || entry.RuleID == "959100" {
				entry.IsBlocking = true
			}
		}

		// Parse message
		if matches := msgRe.FindStringSubmatch(line); len(matches) > 1 {
			entry.Message = matches[1]
			// Extract total score from blocking messages
			if scoreMatches := totalScoreRe.FindStringSubmatch(entry.Message); len(scoreMatches) > 1 {
				if score, err := strconv.Atoi(scoreMatches[1]); err == nil {
					entry.TotalScore = score
				}
			}
		}

		// Parse severity
		if matches := severityRe.FindStringSubmatch(line); len(matches) > 1 {
			entry.Severity = strings.ToUpper(matches[1])
		}

		// Parse hostname
		if matches := hostnameRe.FindStringSubmatch(line); len(matches) > 1 {
			entry.Hostname = matches[1]
		}

		// Parse URI
		if matches := uriRe.FindStringSubmatch(line); len(matches) > 1 {
			entry.URI = matches[1]
		}

		// Parse unique ID
		if matches := uniqueIDRe.FindStringSubmatch(line); len(matches) > 1 {
			entry.UniqueID = matches[1]
		}

		// Parse file
		if matches := fileRe.FindStringSubmatch(line); len(matches) > 1 {
			entry.RuleFile = matches[1]
		}

		// Parse matched data
		if matches := dataRe.FindStringSubmatch(line); len(matches) > 1 {
			entry.RuleData = matches[1]
		}

		// Parse CRS version
		if matches := verRe.FindStringSubmatch(line); len(matches) > 1 {
			entry.CRSVersion = matches[1]
		}

		// Parse all tags
		tagMatches := tagRe.FindAllStringSubmatch(line, -1)
		for _, match := range tagMatches {
			if len(match) > 1 {
				entry.Tags = append(entry.Tags, match[1])
				// Extract paranoia level from tags
				if plMatch := paranoiaRe.FindStringSubmatch(match[1]); len(plMatch) > 1 {
					if pl, err := strconv.Atoi(plMatch[1]); err == nil {
						entry.ParanoiaLevel = pl
					}
				}
				// Extract attack type from tags
				if atMatch := attackTypeRe.FindStringSubmatch(match[1]); len(atMatch) > 1 {
					entry.AttackType = atMatch[1]
				}
			}
		}

		// Only add entries with valid rule ID
		if entry.RuleID != "" && entry.SrcIP != "" {
			entries = append(entries, entry)
		}
	}

	c.logger.Info("Parse complete", "security2_lines", securityErrorCount, "valid_entries", len(entries))
	return entries, nil
}

// TestConnection tests the SSH connection to XGS
func (c *Client) TestConnection(ctx context.Context) error {
	if c.host == "" {
		return fmt.Errorf("sophos SSH host not configured")
	}

	// Read SSH key
	key, err := os.ReadFile(c.keyPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to parse SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: c.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	client.Close()

	return nil
}
