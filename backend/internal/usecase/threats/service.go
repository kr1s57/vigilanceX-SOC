package threats

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/external/threatintel"
	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// Service handles threat intelligence business logic
type Service struct {
	repo       *clickhouse.ThreatsRepository
	aggregator *threatintel.Aggregator
}

// NewService creates a new threats service
func NewService(repo *clickhouse.ThreatsRepository, aggregator *threatintel.Aggregator) *Service {
	return &Service{
		repo:       repo,
		aggregator: aggregator,
	}
}

// CheckIP queries threat intel and returns aggregated result
func (s *Service) CheckIP(ctx context.Context, ip string) (*threatintel.AggregatedResult, error) {
	// Query all threat intel sources
	result, err := s.aggregator.CheckIP(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("check threat intel: %w", err)
	}

	// Save to database for historical tracking
	if !result.CacheHit {
		go s.saveThreatScore(ip, result)
	}

	return result, nil
}

// saveThreatScore persists the threat score to ClickHouse
func (s *Service) saveThreatScore(ip string, result *threatintel.AggregatedResult) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	score := &entity.ThreatScore{
		IP:              ip,
		AggregatedScore: int32(result.AggregatedScore),
		ThreatLevel:     result.ThreatLevel,
		Confidence:      result.Confidence,
		Country:         result.Country,
		ASN:             result.ASN,
		ISP:             result.ISP,
		IsTor:           result.IsTor,
		LastChecked:     result.LastChecked,
	}

	// Individual source scores (v1.6: 7 providers)
	for _, source := range result.Sources {
		switch source.Provider {
		case "AbuseIPDB":
			score.AbuseIPDBScore = int32(source.Score)
		case "VirusTotal":
			score.VirusTotalScore = int32(source.Score)
		case "AlienVault OTX":
			score.OTXScore = int32(source.Score)
		case "GreyNoise":
			score.GreyNoiseScore = int32(source.Score)
			score.IsBenign = source.IsBenignSource
		case "IPSum":
			score.IPSumScore = int32(source.Score)
		case "CriminalIP":
			score.CriminalIPScore = int32(source.Score)
		case "Pulsedive":
			score.PulsediveScore = int32(source.Score)
		}
	}

	// v1.6: Store additional flags from aggregated result
	score.IsVPN = result.IsVPN
	score.IsProxy = result.IsProxy
	score.InBlocklists = int32(result.InBlocklists)

	// Metadata
	if len(result.MalwareFamilies) > 0 {
		score.MalwareFamilies = result.MalwareFamilies
	}
	if len(result.Adversaries) > 0 {
		score.Adversaries = result.Adversaries
	}
	if len(result.Tags) > 0 {
		score.Tags = result.Tags
	}

	if err := s.repo.UpsertThreatScore(ctx, score); err != nil {
		log.Printf("[ERROR] Failed to save threat score for %s: %v", ip, err)
	}
}

// GetThreatScore retrieves stored threat score for an IP
func (s *Service) GetThreatScore(ctx context.Context, ip string) (*entity.ThreatScore, error) {
	return s.repo.GetThreatScore(ctx, ip)
}

// GetTopThreats returns IPs with highest threat scores
func (s *Service) GetTopThreats(ctx context.Context, limit int) ([]entity.ThreatScore, error) {
	if limit <= 0 {
		limit = 20
	}
	return s.repo.GetTopThreats(ctx, limit)
}

// GetThreatsByLevel returns IPs filtered by threat level
func (s *Service) GetThreatsByLevel(ctx context.Context, level string, limit int) ([]entity.ThreatScore, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.repo.GetThreatsByLevel(ctx, level, limit)
}

// GetThreatStats returns threat intelligence statistics
func (s *Service) GetThreatStats(ctx context.Context) (*ThreatStats, error) {
	entityStats, err := s.repo.GetThreatStats(ctx)
	if err != nil {
		return nil, err
	}

	// Build response with embedded entity stats
	stats := &ThreatStats{
		ThreatStats: *entityStats,
		CacheStats:  s.aggregator.GetCacheStats(),
	}
	stats.ConfiguredProviders = s.aggregator.GetConfiguredProviders()

	return stats, nil
}

// ThreatStats extends entity.ThreatStats with cache info
type ThreatStats struct {
	entity.ThreatStats
	CacheStats threatintel.CacheStats `json:"cache_stats"`
}

// EnrichEvent enriches an event with threat intel
func (s *Service) EnrichEvent(ctx context.Context, event *entity.Event) (*entity.Event, error) {
	if event.SrcIP == "" {
		return event, nil
	}

	// Check if we already have a cached/stored score
	score, err := s.repo.GetThreatScore(ctx, event.SrcIP)
	if err == nil && score != nil {
		// Use stored score
		event.ThreatScore = int(score.AggregatedScore)
		event.ThreatLevel = score.ThreatLevel
		return event, nil
	}

	// Query threat intel (will use cache if available)
	result, err := s.aggregator.CheckIP(ctx, event.SrcIP)
	if err != nil {
		log.Printf("[WARN] Failed to enrich event with threat intel: %v", err)
		return event, nil
	}

	event.ThreatScore = result.AggregatedScore
	event.ThreatLevel = result.ThreatLevel

	return event, nil
}

// BatchEnrichIPs enriches multiple IPs with threat intel
func (s *Service) BatchEnrichIPs(ctx context.Context, ips []string) (map[string]*threatintel.AggregatedResult, error) {
	results := make(map[string]*threatintel.AggregatedResult)

	for _, ip := range ips {
		result, err := s.CheckIP(ctx, ip)
		if err != nil {
			log.Printf("[WARN] Failed to check IP %s: %v", ip, err)
			continue
		}
		results[ip] = result
	}

	return results, nil
}

// ShouldAutoBan determines if an IP should be automatically banned based on threat score
func (s *Service) ShouldAutoBan(ctx context.Context, ip string, threshold int) (bool, string, error) {
	result, err := s.CheckIP(ctx, ip)
	if err != nil {
		return false, "", err
	}

	if threshold <= 0 {
		threshold = 80 // Default critical threshold
	}

	if result.AggregatedScore >= threshold {
		reason := fmt.Sprintf("Threat score %d (%s) - Auto-ban threshold: %d",
			result.AggregatedScore, result.ThreatLevel, threshold)
		return true, reason, nil
	}

	return false, "", nil
}

// ClearCache clears the threat intel cache
func (s *Service) ClearCache() {
	s.aggregator.ClearCache()
}

// GetProviderStatus returns the status of all threat intel providers
// v1.6: Returns all 7 providers with descriptions
func (s *Service) GetProviderStatus() []threatintel.ProviderStatus {
	return s.aggregator.GetProviderStatus()
}
