package blocklist

import "time"

// FeedSource represents a blocklist feed source
type FeedSource struct {
	Name           string        // Unique identifier
	DisplayName    string        // Human-readable name
	URL            string        // Download URL
	Category       string        // Primary threat category
	Confidence     int           // Default confidence level (0-100)
	RefreshInterval time.Duration // How often to refresh
	Format         FeedFormat    // Parsing format
	Enabled        bool          // Whether to use this feed
}

// FeedFormat defines how to parse the feed
type FeedFormat string

const (
	FormatIPList      FeedFormat = "ip_list"       // One IP per line
	FormatNetset      FeedFormat = "netset"        // Firehol format (IP/CIDR with comments)
	FormatCIDRList    FeedFormat = "cidr_list"     // CIDR ranges
	FormatDShield     FeedFormat = "dshield"       // DShield format (Start\tEnd\tCount)
	FormatSpamhaus    FeedFormat = "spamhaus"      // Spamhaus DROP format
)

// ThreatCategory constants
const (
	CategoryBotnet   = "botnet"
	CategoryC2       = "c2"
	CategorySpam     = "spam"
	CategoryScanner  = "scanner"
	CategoryMalware  = "malware"
	CategoryAttacker = "attacker"
	CategoryMixed    = "mixed"
)

// DefaultFeeds returns all configured blocklist feeds
func DefaultFeeds() []FeedSource {
	return []FeedSource{
		// Firehol - Aggregated lists (highly curated)
		{
			Name:           "firehol_level1",
			DisplayName:    "Firehol Level 1",
			URL:            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
			Category:       CategoryMixed,
			Confidence:     90,
			RefreshInterval: 1 * time.Hour,
			Format:         FormatNetset,
			Enabled:        true,
		},
		{
			Name:           "firehol_level2",
			DisplayName:    "Firehol Level 2",
			URL:            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
			Category:       CategoryMixed,
			Confidence:     75,
			RefreshInterval: 2 * time.Hour,
			Format:         FormatNetset,
			Enabled:        true,
		},
		// Feodo Tracker - Botnet C2 servers (Emotet, Dridex, TrickBot, QakBot)
		{
			Name:           "feodo_tracker",
			DisplayName:    "Feodo Tracker (Botnets)",
			URL:            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
			Category:       CategoryBotnet,
			Confidence:     95,
			RefreshInterval: 30 * time.Minute,
			Format:         FormatIPList,
			Enabled:        true,
		},
		// Emerging Threats - Compromised IPs
		{
			Name:           "emerging_threats",
			DisplayName:    "Emerging Threats",
			URL:            "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
			Category:       CategoryAttacker,
			Confidence:     85,
			RefreshInterval: 1 * time.Hour,
			Format:         FormatIPList,
			Enabled:        true,
		},
		// Spamhaus DROP - Hijacked IP ranges
		{
			Name:           "spamhaus_drop",
			DisplayName:    "Spamhaus DROP",
			URL:            "https://www.spamhaus.org/drop/drop.txt",
			Category:       CategoryMalware,
			Confidence:     95,
			RefreshInterval: 4 * time.Hour,
			Format:         FormatSpamhaus,
			Enabled:        true,
		},
		// Spamhaus EDROP - Extended DROP
		{
			Name:           "spamhaus_edrop",
			DisplayName:    "Spamhaus EDROP",
			URL:            "https://www.spamhaus.org/drop/edrop.txt",
			Category:       CategoryMalware,
			Confidence:     95,
			RefreshInterval: 4 * time.Hour,
			Format:         FormatSpamhaus,
			Enabled:        true,
		},
		// DShield - Top attackers
		{
			Name:           "dshield",
			DisplayName:    "DShield Top Attackers",
			URL:            "https://www.dshield.org/block.txt",
			Category:       CategoryScanner,
			Confidence:     80,
			RefreshInterval: 1 * time.Hour,
			Format:         FormatDShield,
			Enabled:        true,
		},
		// Binary Defense - Banned IPs
		{
			Name:           "binary_defense",
			DisplayName:    "Binary Defense",
			URL:            "https://www.binarydefense.com/banlist.txt",
			Category:       CategoryAttacker,
			Confidence:     85,
			RefreshInterval: 1 * time.Hour,
			Format:         FormatIPList,
			Enabled:        true,
		},
		// CI Army - Bad actors
		{
			Name:           "ci_army",
			DisplayName:    "CI Army Bad Guys",
			URL:            "https://cinsscore.com/list/ci-badguys.txt",
			Category:       CategoryAttacker,
			Confidence:     80,
			RefreshInterval: 2 * time.Hour,
			Format:         FormatIPList,
			Enabled:        true,
		},
		// Abuse.ch SSL Blacklist (C2)
		{
			Name:           "sslbl_aggressive",
			DisplayName:    "Abuse.ch SSL Blacklist",
			URL:            "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.txt",
			Category:       CategoryC2,
			Confidence:     90,
			RefreshInterval: 30 * time.Minute,
			Format:         FormatIPList,
			Enabled:        true,
		},
		// Blocklist.de - All attacks
		{
			Name:           "blocklist_de",
			DisplayName:    "Blocklist.de All",
			URL:            "https://lists.blocklist.de/lists/all.txt",
			Category:       CategoryAttacker,
			Confidence:     75,
			RefreshInterval: 1 * time.Hour,
			Format:         FormatIPList,
			Enabled:        true,
		},
	}
}

// GetFeedByName returns a specific feed by name
func GetFeedByName(name string) *FeedSource {
	for _, feed := range DefaultFeeds() {
		if feed.Name == name {
			return &feed
		}
	}
	return nil
}

// GetEnabledFeeds returns only enabled feeds
func GetEnabledFeeds() []FeedSource {
	var enabled []FeedSource
	for _, feed := range DefaultFeeds() {
		if feed.Enabled {
			enabled = append(enabled, feed)
		}
	}
	return enabled
}
