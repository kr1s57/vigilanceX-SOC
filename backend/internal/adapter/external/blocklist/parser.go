package blocklist

import (
	"bufio"
	"net"
	"regexp"
	"strings"
)

// ParsedIP represents a parsed IP from a blocklist
type ParsedIP struct {
	IP       string // Single IP or start of range
	EndIP    string // End of range (for CIDR expansion)
	IsCIDR   bool   // Whether this was a CIDR notation
	Original string // Original line for debugging
}

// Parser handles parsing of different blocklist formats
type Parser struct{}

// NewParser creates a new blocklist parser
func NewParser() *Parser {
	return &Parser{}
}

// ipv4Regex matches valid IPv4 addresses
var ipv4Regex = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// cidrRegex matches CIDR notation
var cidrRegex = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})`)

// Parse parses content based on the feed format
func (p *Parser) Parse(content string, format FeedFormat) []ParsedIP {
	switch format {
	case FormatIPList:
		return p.parseIPList(content)
	case FormatNetset:
		return p.parseNetset(content)
	case FormatCIDRList:
		return p.parseCIDRList(content)
	case FormatDShield:
		return p.parseDShield(content)
	case FormatSpamhaus:
		return p.parseSpamhaus(content)
	default:
		return p.parseIPList(content)
	}
}

// parseIPList parses simple IP list (one IP per line)
func (p *Parser) parseIPList(content string) []ParsedIP {
	var results []ParsedIP
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Extract IP from line (handles trailing comments)
		if match := ipv4Regex.FindString(line); match != "" {
			if isValidIP(match) {
				results = append(results, ParsedIP{
					IP:       match,
					Original: line,
				})
			}
		}
	}

	return results
}

// parseNetset parses Firehol netset format (IP/CIDR with comments)
func (p *Parser) parseNetset(content string) []ParsedIP {
	var results []ParsedIP
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for CIDR notation
		if match := cidrRegex.FindStringSubmatch(line); len(match) >= 3 {
			ip := match[1]
			mask := match[2]

			// Expand small CIDR blocks, keep large ones as single entry
			ips := expandCIDR(ip + "/" + mask)
			for _, expandedIP := range ips {
				results = append(results, ParsedIP{
					IP:       expandedIP,
					IsCIDR:   true,
					Original: line,
				})
			}
		} else if match := ipv4Regex.FindString(line); match != "" {
			// Single IP
			if isValidIP(match) {
				results = append(results, ParsedIP{
					IP:       match,
					Original: line,
				})
			}
		}
	}

	return results
}

// parseCIDRList parses CIDR list format
func (p *Parser) parseCIDRList(content string) []ParsedIP {
	return p.parseNetset(content) // Same logic
}

// parseDShield parses DShield format (Start\tEnd\tAttacks)
func (p *Parser) parseDShield(content string) []ParsedIP {
	var results []ParsedIP
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split by tab
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			startIP := parts[0]
			endIP := parts[1]

			if isValidIP(startIP) {
				// For /24 blocks, just use the start IP with .0
				// DShield typically lists /24 blocks
				results = append(results, ParsedIP{
					IP:       startIP,
					EndIP:    endIP,
					Original: line,
				})
			}
		}
	}

	return results
}

// parseSpamhaus parses Spamhaus DROP/EDROP format
func (p *Parser) parseSpamhaus(content string) []ParsedIP {
	var results []ParsedIP
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Format: CIDR ; SBL_ID
		parts := strings.Split(line, ";")
		if len(parts) >= 1 {
			cidr := strings.TrimSpace(parts[0])

			if match := cidrRegex.FindStringSubmatch(cidr); len(match) >= 3 {
				ip := match[1]
				mask := match[2]

				// Expand CIDR (limited to /24 and smaller to avoid huge expansions)
				ips := expandCIDR(ip + "/" + mask)
				for _, expandedIP := range ips {
					results = append(results, ParsedIP{
						IP:       expandedIP,
						IsCIDR:   true,
						Original: line,
					})
				}
			}
		}
	}

	return results
}

// isValidIP checks if the string is a valid IPv4 address
func isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// Check it's IPv4
	if parsed.To4() == nil {
		return false
	}

	// Skip private/reserved ranges
	if isPrivateIP(parsed) {
		return false
	}

	return true
}

// isPrivateIP checks if IP is private/reserved
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"0.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// expandCIDR expands a CIDR block to individual IPs
// Limited to /24 and smaller to avoid huge expansions
func expandCIDR(cidr string) []string {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		if ip := net.ParseIP(strings.Split(cidr, "/")[0]); ip != nil {
			return []string{ip.String()}
		}
		return nil
	}

	// Get mask size
	ones, bits := network.Mask.Size()

	// For large blocks (< /24), just return the network address
	// to avoid memory issues (a /16 would be 65536 IPs!)
	if ones < 24 {
		// Return representative IP for the block
		return []string{network.IP.String()}
	}

	// For /24 and smaller, expand all IPs
	var ips []string
	numIPs := 1 << (bits - ones)

	// Safety limit
	if numIPs > 256 {
		return []string{network.IP.String()}
	}

	ip := network.IP.To4()
	if ip == nil {
		return nil
	}

	for i := 0; i < numIPs; i++ {
		currentIP := make(net.IP, 4)
		copy(currentIP, ip)

		// Add offset
		offset := uint32(i)
		currentIP[3] += byte(offset)
		currentIP[2] += byte(offset >> 8)
		currentIP[1] += byte(offset >> 16)
		currentIP[0] += byte(offset >> 24)

		// Skip network and broadcast for /24+
		if ones >= 24 && (i == 0 || i == numIPs-1) {
			continue
		}

		if !isPrivateIP(currentIP) {
			ips = append(ips, currentIP.String())
		}
	}

	return ips
}
