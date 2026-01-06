package geolocation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// join concatenates strings with a separator
func join(strs []string, sep string) string {
	return strings.Join(strs, sep)
}

// IPGeoInfo represents geolocation data for an IP
type IPGeoInfo struct {
	IP          string  `json:"query"`
	CountryCode string  `json:"countryCode"`
	CountryName string  `json:"country"`
	City        string  `json:"city"`
	Region      string  `json:"regionName"`
	Latitude    float64 `json:"lat"`
	Longitude   float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	ASNumber    uint32  `json:"-"`
	ASName      string  `json:"-"`
	IsProxy     bool    `json:"proxy"`
	IsHosting   bool    `json:"hosting"`
	Status      string  `json:"status"`
	Message     string  `json:"message"`
}

// Service handles IP geolocation lookups
type Service struct {
	db         driver.Conn
	logger     *slog.Logger
	httpClient *http.Client
	cache      map[string]*IPGeoInfo
	cacheMu    sync.RWMutex
	rateLimit  chan struct{}
}

// NewService creates a new geolocation service
func NewService(db driver.Conn, logger *slog.Logger) *Service {
	return &Service{
		db:     db,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache:     make(map[string]*IPGeoInfo),
		rateLimit: make(chan struct{}, 5), // Max 5 concurrent requests
	}
}

// LookupIP gets geolocation for a single IP (with caching)
func (s *Service) LookupIP(ctx context.Context, ip string) (*IPGeoInfo, error) {
	// Check memory cache first
	s.cacheMu.RLock()
	if cached, ok := s.cache[ip]; ok {
		s.cacheMu.RUnlock()
		return cached, nil
	}
	s.cacheMu.RUnlock()

	// Check database
	geo, err := s.getFromDB(ctx, ip)
	if err == nil && geo != nil {
		s.cacheMu.Lock()
		s.cache[ip] = geo
		s.cacheMu.Unlock()
		return geo, nil
	}

	// Fetch from API
	geo, err = s.fetchFromAPI(ctx, ip)
	if err != nil {
		return nil, err
	}

	// Store in DB and cache
	if err := s.storeToDB(ctx, geo); err != nil {
		s.logger.Warn("Failed to store geolocation", "ip", ip, "error", err)
	}

	s.cacheMu.Lock()
	s.cache[ip] = geo
	s.cacheMu.Unlock()

	return geo, nil
}

// LookupBatch gets geolocation for multiple IPs
func (s *Service) LookupBatch(ctx context.Context, ips []string) (map[string]*IPGeoInfo, error) {
	results := make(map[string]*IPGeoInfo)
	var toFetch []string

	// Check cache and DB first
	for _, ip := range ips {
		s.cacheMu.RLock()
		if cached, ok := s.cache[ip]; ok {
			results[ip] = cached
			s.cacheMu.RUnlock()
			continue
		}
		s.cacheMu.RUnlock()

		geo, err := s.getFromDB(ctx, ip)
		if err == nil && geo != nil {
			results[ip] = geo
			s.cacheMu.Lock()
			s.cache[ip] = geo
			s.cacheMu.Unlock()
			continue
		}

		toFetch = append(toFetch, ip)
	}

	// Fetch missing IPs from API (with rate limiting)
	for _, ip := range toFetch {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case s.rateLimit <- struct{}{}:
			geo, err := s.fetchFromAPI(ctx, ip)
			<-s.rateLimit

			if err != nil {
				s.logger.Warn("Failed to fetch geolocation", "ip", ip, "error", err)
				continue
			}

			results[ip] = geo
			if err := s.storeToDB(ctx, geo); err != nil {
				s.logger.Warn("Failed to store geolocation", "ip", ip, "error", err)
			}

			s.cacheMu.Lock()
			s.cache[ip] = geo
			s.cacheMu.Unlock()

			// Rate limit: ip-api.com allows 45 requests/minute for free
			time.Sleep(150 * time.Millisecond)
		}
	}

	return results, nil
}

// getFromDB retrieves geolocation from ClickHouse
func (s *Service) getFromDB(ctx context.Context, ip string) (*IPGeoInfo, error) {
	query := `
		SELECT
			IPv4NumToString(ip), country_code, country_name, city, region,
			latitude, longitude, isp, org, as_number, as_name, is_proxy, is_hosting
		FROM ip_geolocation
		WHERE ip = toIPv4(?)
		LIMIT 1
	`

	var geo IPGeoInfo
	var isProxy, isHosting uint8
	err := s.db.QueryRow(ctx, query, ip).Scan(
		&geo.IP, &geo.CountryCode, &geo.CountryName, &geo.City, &geo.Region,
		&geo.Latitude, &geo.Longitude, &geo.ISP, &geo.Org, &geo.ASNumber, &geo.ASName,
		&isProxy, &isHosting,
	)
	if err != nil {
		return nil, err
	}

	geo.IsProxy = isProxy == 1
	geo.IsHosting = isHosting == 1
	return &geo, nil
}

// fetchFromAPI fetches geolocation from ip-api.com
func (s *Service) fetchFromAPI(ctx context.Context, ip string) (*IPGeoInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting,query", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch geolocation: %w", err)
	}
	defer resp.Body.Close()

	var geo IPGeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if geo.Status != "success" {
		return nil, fmt.Errorf("geolocation lookup failed: %s", geo.Message)
	}

	// Parse AS number from AS string (format: "AS12345 ISP Name")
	if geo.AS != "" {
		var asNum uint32
		fmt.Sscanf(geo.AS, "AS%d", &asNum)
		geo.ASNumber = asNum
		geo.ASName = geo.AS
	}

	return &geo, nil
}

// storeToDB stores geolocation in ClickHouse
func (s *Service) storeToDB(ctx context.Context, geo *IPGeoInfo) error {
	query := `
		INSERT INTO ip_geolocation (
			ip, country_code, country_name, city, region,
			latitude, longitude, isp, org, as_number, as_name,
			is_proxy, is_hosting, updated_at
		) VALUES (
			toIPv4(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now()
		)
	`

	isProxy := uint8(0)
	if geo.IsProxy {
		isProxy = 1
	}
	isHosting := uint8(0)
	if geo.IsHosting {
		isHosting = 1
	}

	return s.db.Exec(ctx, query,
		geo.IP, geo.CountryCode, geo.CountryName, geo.City, geo.Region,
		geo.Latitude, geo.Longitude, geo.ISP, geo.Org, geo.ASNumber, geo.ASName,
		isProxy, isHosting,
	)
}

// RefreshOldEntries refreshes geolocation data older than specified duration
func (s *Service) RefreshOldEntries(ctx context.Context, olderThan time.Duration) (int, error) {
	// Get IPs with old geolocation data
	query := `
		SELECT DISTINCT IPv4NumToString(ip)
		FROM ip_geolocation
		WHERE updated_at < now() - toIntervalDay(?)
		LIMIT 1000
	`

	days := int(olderThan.Hours() / 24)
	rows, err := s.db.Query(ctx, query, days)
	if err != nil {
		return 0, fmt.Errorf("failed to query old entries: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue
		}
		ips = append(ips, ip)
	}

	if len(ips) == 0 {
		return 0, nil
	}

	s.logger.Info("Refreshing old geolocation entries", "count", len(ips))

	refreshed := 0
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return refreshed, ctx.Err()
		default:
		}

		geo, err := s.fetchFromAPI(ctx, ip)
		if err != nil {
			s.logger.Warn("Failed to refresh geolocation", "ip", ip, "error", err)
			continue
		}

		if err := s.storeToDB(ctx, geo); err != nil {
			s.logger.Warn("Failed to store refreshed geolocation", "ip", ip, "error", err)
			continue
		}

		refreshed++
		time.Sleep(150 * time.Millisecond) // Rate limiting
	}

	return refreshed, nil
}

// GetGeoForIPs retrieves geolocation for a list of IPs from DB only (fast, no API calls)
func (s *Service) GetGeoForIPs(ctx context.Context, ips []string) (map[string]*IPGeoInfo, error) {
	if len(ips) == 0 {
		return make(map[string]*IPGeoInfo), nil
	}

	// Build query with IN clause using proper IPv4 formatting
	// ClickHouse requires explicit IPv4 conversion for each value
	placeholders := make([]string, len(ips))
	args := make([]interface{}, len(ips))
	for i, ip := range ips {
		placeholders[i] = "toIPv4(?)"
		args[i] = ip
	}

	query := fmt.Sprintf(`
		SELECT
			IPv4NumToString(ip), country_code, country_name, city, region,
			latitude, longitude, isp, org, as_number, as_name, is_proxy, is_hosting
		FROM ip_geolocation
		WHERE ip IN (%s)
	`, join(placeholders, ","))

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query geolocation: %w", err)
	}
	defer rows.Close()

	results := make(map[string]*IPGeoInfo)
	for rows.Next() {
		var geo IPGeoInfo
		var isProxy, isHosting uint8
		if err := rows.Scan(
			&geo.IP, &geo.CountryCode, &geo.CountryName, &geo.City, &geo.Region,
			&geo.Latitude, &geo.Longitude, &geo.ISP, &geo.Org, &geo.ASNumber, &geo.ASName,
			&isProxy, &isHosting,
		); err != nil {
			continue
		}
		geo.IsProxy = isProxy == 1
		geo.IsHosting = isHosting == 1
		results[geo.IP] = &geo
	}

	return results, nil
}

// EnrichNewIPs looks up geolocation for IPs that don't exist in DB yet
func (s *Service) EnrichNewIPs(ctx context.Context, ips []string) error {
	if len(ips) == 0 {
		return nil
	}

	// Find IPs not in DB
	existing, err := s.GetGeoForIPs(ctx, ips)
	if err != nil {
		return err
	}

	var newIPs []string
	for _, ip := range ips {
		if _, exists := existing[ip]; !exists {
			newIPs = append(newIPs, ip)
		}
	}

	if len(newIPs) == 0 {
		return nil
	}

	s.logger.Info("Enriching new IPs with geolocation", "count", len(newIPs))

	// Fetch and store new IPs
	_, err = s.LookupBatch(ctx, newIPs)
	return err
}
