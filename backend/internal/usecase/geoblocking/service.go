package geoblocking

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"

	"github.com/kr1s57/vigilancex/internal/adapter/external/geoip"
	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// Service handles geoblocking business logic (v2.0)
type Service struct {
	repo      *clickhouse.GeoblockingRepository
	geoClient *geoip.Client
	mu        sync.RWMutex
	// Cached rules for fast lookup
	cachedRules []entity.GeoBlockRule
}

// NewService creates a new geoblocking service
func NewService(repo *clickhouse.GeoblockingRepository, geoClient *geoip.Client) *Service {
	s := &Service{
		repo:      repo,
		geoClient: geoClient,
	}

	// Load rules into cache
	s.RefreshRulesCache(context.Background())

	return s
}

// RefreshRulesCache reloads rules from database into cache
func (s *Service) RefreshRulesCache(ctx context.Context) error {
	rules, err := s.repo.GetActiveRules(ctx)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}

	s.mu.Lock()
	s.cachedRules = rules
	s.mu.Unlock()

	log.Printf("[GEOBLOCK] Rules cache refreshed: %d rules", len(rules))
	return nil
}

// GetRules returns all geoblocking rules
func (s *Service) GetRules(ctx context.Context) ([]entity.GeoBlockRule, error) {
	return s.repo.GetAllRules(ctx)
}

// GetActiveRules returns only active rules
func (s *Service) GetActiveRules(ctx context.Context) ([]entity.GeoBlockRule, error) {
	return s.repo.GetActiveRules(ctx)
}

// GetRulesByType returns rules filtered by type
func (s *Service) GetRulesByType(ctx context.Context, ruleType string) ([]entity.GeoBlockRule, error) {
	return s.repo.GetRulesByType(ctx, ruleType)
}

// CreateRule creates a new geoblocking rule
func (s *Service) CreateRule(ctx context.Context, req *entity.GeoBlockRequest) (*entity.GeoBlockRule, error) {
	// Validate rule type
	validTypes := map[string]bool{
		entity.GeoRuleTypeCountryBlock: true,
		entity.GeoRuleTypeCountryWatch: true,
		entity.GeoRuleTypeASNBlock:     true,
		entity.GeoRuleTypeASNWatch:     true,
	}
	if !validTypes[req.RuleType] {
		return nil, fmt.Errorf("invalid rule type: %s", req.RuleType)
	}

	// Validate action
	validActions := map[string]bool{
		entity.GeoActionBlock: true,
		entity.GeoActionWatch: true,
		entity.GeoActionBoost: true,
	}
	if !validActions[req.Action] {
		return nil, fmt.Errorf("invalid action: %s", req.Action)
	}

	// Validate target based on rule type
	if req.RuleType == entity.GeoRuleTypeCountryBlock || req.RuleType == entity.GeoRuleTypeCountryWatch {
		if len(req.Target) != 2 {
			return nil, fmt.Errorf("country code must be 2 characters (ISO 3166-1 alpha-2)")
		}
	} else if req.RuleType == entity.GeoRuleTypeASNBlock || req.RuleType == entity.GeoRuleTypeASNWatch {
		if _, err := strconv.ParseUint(req.Target, 10, 32); err != nil {
			return nil, fmt.Errorf("ASN must be a numeric value")
		}
	}

	rule := &entity.GeoBlockRule{
		RuleType:      req.RuleType,
		Target:        req.Target,
		Action:        req.Action,
		ScoreModifier: req.ScoreModifier,
		Reason:        req.Reason,
		IsActive:      true,
		CreatedBy:     req.CreatedBy,
	}

	if err := s.repo.CreateRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}

	// Refresh cache
	s.RefreshRulesCache(ctx)

	log.Printf("[GEOBLOCK] Rule created: type=%s target=%s action=%s", rule.RuleType, rule.Target, rule.Action)

	return rule, nil
}

// UpdateRule updates an existing rule
func (s *Service) UpdateRule(ctx context.Context, rule *entity.GeoBlockRule) error {
	if err := s.repo.UpdateRule(ctx, rule); err != nil {
		return fmt.Errorf("update rule: %w", err)
	}

	// Refresh cache
	s.RefreshRulesCache(ctx)

	return nil
}

// DeleteRule deletes a rule by ID
func (s *Service) DeleteRule(ctx context.Context, id string) error {
	if err := s.repo.DeleteRule(ctx, id); err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}

	// Refresh cache
	s.RefreshRulesCache(ctx)

	log.Printf("[GEOBLOCK] Rule deleted: id=%s", id)
	return nil
}

// GetStats returns geoblocking statistics
func (s *Service) GetStats(ctx context.Context) (*entity.GeoBlockStats, error) {
	return s.repo.GetStats(ctx)
}

// CheckIP performs a full geoblocking check for an IP
func (s *Service) CheckIP(ctx context.Context, ip string) (*entity.GeoCheckResult, error) {
	result := &entity.GeoCheckResult{
		IP:           ip,
		MatchedRules: []entity.GeoBlockRule{},
		RiskFactors:  []string{},
	}

	// Get geolocation
	geo, err := s.geoClient.Lookup(ctx, ip)
	if err != nil {
		log.Printf("[GEOBLOCK] Geolocation lookup failed for %s: %v", ip, err)
		// Continue without geo data
	} else {
		result.GeoLocation = geo

		// Cache geolocation in database
		if err := s.repo.SaveGeoLocation(ctx, geo); err != nil {
			log.Printf("[GEOBLOCK] Failed to cache geolocation for %s: %v", ip, err)
		}

		// Check for infrastructure risk factors
		if geo.IsVPN {
			result.RiskFactors = append(result.RiskFactors, "vpn")
		}
		if geo.IsProxy {
			result.RiskFactors = append(result.RiskFactors, "proxy")
		}
		if geo.IsTor {
			result.RiskFactors = append(result.RiskFactors, "tor")
		}
		if geo.IsDatacenter {
			result.RiskFactors = append(result.RiskFactors, "datacenter")
		}
	}

	// Get cached rules
	s.mu.RLock()
	rules := s.cachedRules
	s.mu.RUnlock()

	// Check country rules
	if geo != nil && geo.CountryCode != "" {
		for _, rule := range rules {
			if !rule.IsActive {
				continue
			}

			// Match country rules
			if (rule.RuleType == entity.GeoRuleTypeCountryBlock || rule.RuleType == entity.GeoRuleTypeCountryWatch) &&
				rule.Target == geo.CountryCode {

				result.MatchedRules = append(result.MatchedRules, rule)
				result.TotalScoreBoost += rule.ScoreModifier

				if rule.Action == entity.GeoActionBlock {
					result.ShouldBlock = true
					result.BlockReason = fmt.Sprintf("Country %s is blocked: %s", geo.CountryCode, rule.Reason)
				}

				result.RiskFactors = append(result.RiskFactors, fmt.Sprintf("country_%s_%s", rule.Action, geo.CountryCode))
			}

			// Match ASN rules
			if geo.ASN > 0 && (rule.RuleType == entity.GeoRuleTypeASNBlock || rule.RuleType == entity.GeoRuleTypeASNWatch) {
				asnStr := strconv.FormatUint(uint64(geo.ASN), 10)
				if rule.Target == asnStr {
					result.MatchedRules = append(result.MatchedRules, rule)
					result.TotalScoreBoost += rule.ScoreModifier

					if rule.Action == entity.GeoActionBlock {
						result.ShouldBlock = true
						result.BlockReason = fmt.Sprintf("ASN %d is blocked: %s", geo.ASN, rule.Reason)
					}

					result.RiskFactors = append(result.RiskFactors, fmt.Sprintf("asn_%s_%d", rule.Action, geo.ASN))
				}
			}
		}
	}

	return result, nil
}

// GetGeoScoreForCountry returns a base risk score for a country
func (s *Service) GetGeoScoreForCountry(countryCode string) int {
	// Check default high-risk countries
	for _, risk := range entity.DefaultHighRiskCountries() {
		if risk.CountryCode == countryCode {
			return risk.BaseScore
		}
	}

	// Check cached rules for score modifier
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rule := range s.cachedRules {
		if rule.IsActive && rule.Target == countryCode &&
			(rule.RuleType == entity.GeoRuleTypeCountryBlock || rule.RuleType == entity.GeoRuleTypeCountryWatch) {
			return rule.ScoreModifier
		}
	}

	return 0 // No special risk
}

// LookupGeo performs a geolocation lookup (with caching)
func (s *Service) LookupGeo(ctx context.Context, ip string) (*entity.GeoLocation, error) {
	// Try database cache first
	cached, err := s.repo.GetGeoLocation(ctx, ip)
	if err == nil {
		return cached, nil
	}

	// Lookup via GeoIP client
	geo, err := s.geoClient.Lookup(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("geolocation lookup: %w", err)
	}

	// Cache in database
	if err := s.repo.SaveGeoLocation(ctx, geo); err != nil {
		log.Printf("[GEOBLOCK] Failed to cache geolocation for %s: %v", ip, err)
	}

	return geo, nil
}

// GetBlockedCountries returns list of blocked country codes
func (s *Service) GetBlockedCountries() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var countries []string
	for _, rule := range s.cachedRules {
		if rule.IsActive && rule.RuleType == entity.GeoRuleTypeCountryBlock {
			countries = append(countries, rule.Target)
		}
	}
	return countries
}

// GetWatchedCountries returns list of watched country codes
func (s *Service) GetWatchedCountries() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var countries []string
	for _, rule := range s.cachedRules {
		if rule.IsActive && rule.RuleType == entity.GeoRuleTypeCountryWatch {
			countries = append(countries, rule.Target)
		}
	}
	return countries
}

// IsCountryBlocked checks if a country is in the block list
func (s *Service) IsCountryBlocked(countryCode string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rule := range s.cachedRules {
		if rule.IsActive && rule.RuleType == entity.GeoRuleTypeCountryBlock && rule.Target == countryCode {
			return true
		}
	}
	return false
}
