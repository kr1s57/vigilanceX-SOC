package crowdsec

import "context"

// BlocklistProvider defines the interface for fetching blocklists
// This can be implemented by either:
// - BlocklistClient (direct CrowdSec API access)
// - VigilanceKeyClient (proxy via VigilanceKey license server)
type BlocklistProvider interface {
	// IsConfigured returns true if the provider is properly configured
	IsConfigured() bool

	// TestConnection tests the API connection
	TestConnection(ctx context.Context) error

	// ListBlocklists returns all available blocklists
	ListBlocklists(ctx context.Context) ([]BlocklistInfo, error)

	// GetSubscribedBlocklists returns blocklists with actual IPs
	GetSubscribedBlocklists(ctx context.Context) ([]BlocklistInfo, error)

	// DownloadBlocklist downloads IPs from a specific blocklist
	DownloadBlocklist(ctx context.Context, blocklistID string) ([]string, error)

	// SetAPIKey sets the API key (no-op for VigilanceKey client)
	SetAPIKey(apiKey string)

	// GetAPIKey returns the current API key
	GetAPIKey() string
}

// Ensure both clients implement the interface
var _ BlocklistProvider = (*BlocklistClient)(nil)
var _ BlocklistProvider = (*VigilanceKeyClient)(nil)
