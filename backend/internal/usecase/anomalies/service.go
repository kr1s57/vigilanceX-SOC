package anomalies

import (
	"context"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// Service handles anomaly detection business logic
type Service struct {
	repo *clickhouse.AnomaliesRepository
}

// NewService creates a new anomalies service
func NewService(repo *clickhouse.AnomaliesRepository) *Service {
	return &Service{repo: repo}
}

// DetectNewIPs finds IPs seen in the last 24h but not in the previous 30 days
func (s *Service) DetectNewIPs(ctx context.Context) ([]entity.NewIPAnomaly, error) {
	return s.repo.GetNewIPs(ctx, 24*time.Hour, 30*24*time.Hour)
}

// DetectSpikes detects statistical anomalies in event counts
func (s *Service) DetectSpikes(ctx context.Context, config *SpikeConfig) ([]entity.Spike, error) {
	if config == nil {
		config = DefaultSpikeConfig()
	}

	// Get hourly event counts for baseline calculation
	baseline, err := s.repo.GetHourlyEventCounts(ctx, config.BaselineWindow)
	if err != nil {
		return nil, fmt.Errorf("get baseline: %w", err)
	}

	// Calculate mean and stddev
	var sum, sumSq float64
	for _, count := range baseline {
		sum += float64(count)
		sumSq += float64(count) * float64(count)
	}

	n := float64(len(baseline))
	if n < 2 {
		return nil, nil // Not enough data
	}

	mean := sum / n
	variance := (sumSq / n) - (mean * mean)
	stddev := math.Sqrt(variance)

	// Get recent counts to check for spikes
	recent, err := s.repo.GetRecentEventCounts(ctx, config.DetectionWindow)
	if err != nil {
		return nil, fmt.Errorf("get recent counts: %w", err)
	}

	var spikes []entity.Spike
	threshold := mean + (config.SigmaThreshold * stddev)

	for timestamp, count := range recent {
		if float64(count) > threshold {
			deviation := (float64(count) - mean) / stddev
			severity := calculateSpikeSeverity(deviation)

			spike := entity.Spike{
				Timestamp:  timestamp,
				EventCount: count,
				Baseline:   int64(mean),
				Threshold:  int64(threshold),
				Deviation:  deviation,
				Severity:   severity,
				DetectedAt: time.Now(),
			}
			spikes = append(spikes, spike)

			// Record the spike
			go s.recordSpike(spike)
		}
	}

	return spikes, nil
}

// SpikeConfig configures spike detection
type SpikeConfig struct {
	BaselineWindow  time.Duration // How far back for baseline (default: 7 days)
	DetectionWindow time.Duration // How far back to check for spikes (default: 1 hour)
	SigmaThreshold  float64       // Standard deviations above mean (default: 3)
	MinEventCount   int64         // Minimum events to consider a spike
}

// DefaultSpikeConfig returns default spike detection config
func DefaultSpikeConfig() *SpikeConfig {
	return &SpikeConfig{
		BaselineWindow:  7 * 24 * time.Hour,
		DetectionWindow: 1 * time.Hour,
		SigmaThreshold:  3.0,
		MinEventCount:   10,
	}
}

// calculateSpikeSeverity determines severity based on standard deviation
func calculateSpikeSeverity(sigma float64) string {
	switch {
	case sigma >= 5:
		return "critical"
	case sigma >= 4:
		return "high"
	case sigma >= 3:
		return "medium"
	default:
		return "low"
	}
}

// recordSpike saves a spike to the database
func (s *Service) recordSpike(spike entity.Spike) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.repo.RecordSpike(ctx, &spike); err != nil {
		log.Printf("[ANOMALY] Failed to record spike: %v", err)
	}
}

// DetectMultiVectorAttack detects IPs using multiple attack vectors
func (s *Service) DetectMultiVectorAttack(ctx context.Context, threshold int) ([]entity.MultiVectorAttack, error) {
	// An IP is suspicious if it triggers events across multiple log types
	// (WAF + IPS, WAF + VPN failures, etc.)
	return s.repo.GetMultiVectorAttackers(ctx, threshold, 1*time.Hour)
}

// DetectTargetedCampaign detects multiple IPs targeting the same resource
func (s *Service) DetectTargetedCampaign(ctx context.Context, threshold int) ([]entity.TargetedCampaign, error) {
	return s.repo.GetTargetedCampaigns(ctx, threshold, 1*time.Hour)
}

// DetectBruteForce detects brute force patterns
func (s *Service) DetectBruteForce(ctx context.Context, config *BruteForceConfig) ([]entity.BruteForcePattern, error) {
	if config == nil {
		config = DefaultBruteForceConfig()
	}

	return s.repo.GetBruteForcePatterns(ctx, config.Threshold, config.Window)
}

// BruteForceConfig configures brute force detection
type BruteForceConfig struct {
	Threshold int           // Failed attempts threshold
	Window    time.Duration // Time window
}

// DefaultBruteForceConfig returns default config
func DefaultBruteForceConfig() *BruteForceConfig {
	return &BruteForceConfig{
		Threshold: 10,
		Window:    5 * time.Minute,
	}
}

// GetRecentAnomalies returns recently detected anomalies
func (s *Service) GetRecentAnomalies(ctx context.Context, limit int) ([]entity.Anomaly, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.repo.GetRecentAnomalies(ctx, limit)
}

// GetAnomalyStats returns anomaly statistics
func (s *Service) GetAnomalyStats(ctx context.Context) (*entity.AnomalyStats, error) {
	return s.repo.GetAnomalyStats(ctx)
}

// RunDetectionCycle runs all anomaly detection checks
func (s *Service) RunDetectionCycle(ctx context.Context) (*DetectionResult, error) {
	result := &DetectionResult{
		Timestamp: time.Now(),
	}

	// Detect new IPs
	newIPs, err := s.DetectNewIPs(ctx)
	if err != nil {
		log.Printf("[ANOMALY] New IP detection failed: %v", err)
	} else {
		result.NewIPs = len(newIPs)
		for _, ip := range newIPs {
			result.Findings = append(result.Findings, AnomalyFinding{
				Type:     "new_ip",
				IP:       ip.IP,
				Severity: "info",
				Details:  fmt.Sprintf("First seen: %s", ip.FirstSeen.Format(time.RFC3339)),
			})
		}
	}

	// Detect spikes
	spikes, err := s.DetectSpikes(ctx, nil)
	if err != nil {
		log.Printf("[ANOMALY] Spike detection failed: %v", err)
	} else {
		result.Spikes = len(spikes)
		for _, spike := range spikes {
			result.Findings = append(result.Findings, AnomalyFinding{
				Type:     "spike",
				Severity: spike.Severity,
				Details:  fmt.Sprintf("Event count: %d (%.1fσ above baseline)", spike.EventCount, spike.Deviation),
			})
		}
	}

	// Detect multi-vector attacks
	multiVector, err := s.DetectMultiVectorAttack(ctx, 2)
	if err != nil {
		log.Printf("[ANOMALY] Multi-vector detection failed: %v", err)
	} else {
		result.MultiVector = len(multiVector)
		for _, attack := range multiVector {
			result.Findings = append(result.Findings, AnomalyFinding{
				Type:     "multi_vector",
				IP:       attack.IP,
				Severity: "high",
				Details:  fmt.Sprintf("Attack vectors: %v", attack.Vectors),
			})
		}
	}

	return result, nil
}

// DetectionResult contains results from a detection cycle
type DetectionResult struct {
	Timestamp   time.Time        `json:"timestamp"`
	NewIPs      int              `json:"new_ips"`
	Spikes      int              `json:"spikes"`
	MultiVector int              `json:"multi_vector"`
	Findings    []AnomalyFinding `json:"findings"`
}

// AnomalyFinding represents a single anomaly finding
type AnomalyFinding struct {
	Type     string `json:"type"`
	IP       string `json:"ip,omitempty"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
}
