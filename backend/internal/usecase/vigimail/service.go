package vigimail

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// Repository interface for Vigimail data persistence
type Repository interface {
	GetConfig(ctx context.Context) (*entity.VigimailConfig, error)
	SaveConfig(ctx context.Context, config *entity.VigimailConfig) error
	UpdateLastCheck(ctx context.Context, lastCheck time.Time) error

	ListDomains(ctx context.Context) ([]entity.VigimailDomain, error)
	AddDomain(ctx context.Context, domain string) (*entity.VigimailDomain, error)
	DeleteDomain(ctx context.Context, domain string) error
	GetDomain(ctx context.Context, domain string) (*entity.VigimailDomain, error)

	ListEmails(ctx context.Context, domain string) ([]entity.VigimailEmail, error)
	ListAllEmails(ctx context.Context) ([]entity.VigimailEmail, error)
	AddEmail(ctx context.Context, email string) (*entity.VigimailEmail, error)
	DeleteEmail(ctx context.Context, email string) error
	UpdateEmailStatus(ctx context.Context, email, status string, leakCount int) error

	GetLeaksForEmail(ctx context.Context, email string) ([]entity.VigimailLeak, error)
	SaveLeaks(ctx context.Context, leaks []entity.VigimailLeak) error
	ClearLeaksForEmail(ctx context.Context, email string) error

	GetLatestDomainCheck(ctx context.Context, domain string) (*entity.DomainDNSCheck, error)
	SaveDomainCheck(ctx context.Context, check *entity.DomainDNSCheck) error
	GetDomainCheckHistory(ctx context.Context, domain string, limit int) ([]entity.DomainDNSCheck, error)

	GetStats(ctx context.Context) (*entity.VigimailStats, error)
	SaveCheckHistory(ctx context.Context, history *entity.VigimailCheckHistory) error

	// Cleanup
	CleanupOrphanLeaks(ctx context.Context) (int, error)
	CleanupOrphanDomainChecks(ctx context.Context) (int, error)
}

// LeakChecker interface for checking email leaks
type LeakChecker interface {
	IsConfigured() bool
	CheckEmail(ctx context.Context, email string) ([]entity.VigimailLeak, error)
	TestConnection(ctx context.Context) error
	SetAPIKey(apiKey string)
	GetAPIKey() string
}

// DNSCheckerInterface for checking domain DNS configuration
type DNSCheckerInterface interface {
	CheckDomain(ctx context.Context, domain string) (*entity.DomainDNSCheck, error)
}

// Service handles Vigimail business logic
type Service struct {
	repo          Repository
	hibpClient    LeakChecker
	leakCheck     LeakChecker
	dnsChecker    DNSCheckerInterface
	config        *entity.VigimailConfig
	worker        *checkWorker
	mu            sync.RWMutex
	stopChan      chan struct{}
	workerRunning bool
}

// NewService creates a new Vigimail service
func NewService(repo Repository, hibpClient LeakChecker, leakCheckClient LeakChecker, dnsChecker DNSCheckerInterface) *Service {
	return &Service{
		repo:       repo,
		hibpClient: hibpClient,
		leakCheck:  leakCheckClient,
		dnsChecker: dnsChecker,
		config:     entity.DefaultVigimailConfig(),
		stopChan:   make(chan struct{}),
	}
}

// Initialize loads configuration and starts worker if enabled
func (s *Service) Initialize(ctx context.Context) error {
	config, err := s.repo.GetConfig(ctx)
	if err != nil {
		slog.Warn("[VIGIMAIL] Failed to load config, using defaults", "error", err)
		config = entity.DefaultVigimailConfig()
	}

	s.mu.Lock()
	s.config = config
	s.mu.Unlock()

	// Update API keys
	if s.hibpClient != nil && config.HIBPAPIKey != "" {
		s.hibpClient.SetAPIKey(config.HIBPAPIKey)
	}
	if s.leakCheck != nil && config.LeakCheckAPIKey != "" {
		s.leakCheck.SetAPIKey(config.LeakCheckAPIKey)
	}

	// Start worker if enabled
	if config.Enabled {
		s.StartWorker()
	}

	slog.Info("[VIGIMAIL] Service initialized", "enabled", config.Enabled, "interval", config.CheckIntervalHours)
	return nil
}

// GetConfig returns the current configuration
func (s *Service) GetConfig(ctx context.Context) (*entity.VigimailConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy
	cfg := *s.config
	return &cfg, nil
}

// UpdateConfig updates the configuration
func (s *Service) UpdateConfig(ctx context.Context, config *entity.VigimailConfig) error {
	s.mu.Lock()

	wasEnabled := s.config.Enabled
	s.config = config

	// Update API keys
	if s.hibpClient != nil {
		s.hibpClient.SetAPIKey(config.HIBPAPIKey)
	}
	if s.leakCheck != nil {
		s.leakCheck.SetAPIKey(config.LeakCheckAPIKey)
	}

	s.mu.Unlock()

	// Persist
	if err := s.repo.SaveConfig(ctx, config); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	// Handle worker state change
	if config.Enabled && !wasEnabled {
		s.StartWorker()
	} else if !config.Enabled && wasEnabled {
		s.StopWorker()
	} else if config.Enabled && wasEnabled {
		// Restart worker with new interval
		s.StopWorker()
		s.StartWorker()
	}

	slog.Info("[VIGIMAIL] Config updated", "enabled", config.Enabled)
	return nil
}

// GetStatus returns the service status
func (s *Service) GetStatus(ctx context.Context) *entity.VigimailStatus {
	s.mu.RLock()
	config := s.config
	workerRunning := s.workerRunning
	s.mu.RUnlock()

	status := &entity.VigimailStatus{
		Enabled:             config.Enabled,
		WorkerRunning:       workerRunning,
		LastCheck:           config.LastCheck,
		HIBPConfigured:      s.hibpClient != nil && s.hibpClient.IsConfigured(),
		LeakCheckConfigured: s.leakCheck != nil && s.leakCheck.IsConfigured(),
	}

	// Calculate next check
	if config.Enabled && !config.LastCheck.IsZero() {
		status.NextCheck = config.LastCheck.Add(time.Duration(config.CheckIntervalHours) * time.Hour)
	}

	// Get stats
	stats, err := s.repo.GetStats(ctx)
	if err == nil {
		status.TotalDomains = stats.TotalDomains
		status.TotalEmails = stats.TotalEmails
		status.TotalLeaks = stats.TotalLeaks
		status.EmailsWithLeaks = stats.EmailsWithLeaks
		status.DomainsAtRisk = stats.DomainsWarning + stats.DomainsCritical
	}

	return status
}

// CleanupOrphanData removes leaks and DNS checks for deleted emails/domains
func (s *Service) CleanupOrphanData(ctx context.Context) (int, error) {
	totalDeleted := 0

	// Cleanup orphan leaks (for deleted emails)
	leaksDeleted, err := s.repo.CleanupOrphanLeaks(ctx)
	if err != nil {
		return 0, fmt.Errorf("cleanup orphan leaks: %w", err)
	}
	totalDeleted += leaksDeleted

	// Cleanup orphan DNS checks (for deleted domains)
	checksDeleted, err := s.repo.CleanupOrphanDomainChecks(ctx)
	if err != nil {
		return totalDeleted, fmt.Errorf("cleanup orphan domain checks: %w", err)
	}
	totalDeleted += checksDeleted

	if totalDeleted > 0 {
		slog.Info("[VIGIMAIL] Orphan data cleanup completed",
			"leaks_deleted", leaksDeleted,
			"checks_deleted", checksDeleted)
	}

	return totalDeleted, nil
}

// ============================================
// Domain Management
// ============================================

// ListDomains returns all monitored domains with enriched data
func (s *Service) ListDomains(ctx context.Context) ([]entity.VigimailDomain, error) {
	domains, err := s.repo.ListDomains(ctx)
	if err != nil {
		return nil, err
	}

	// Enrich with email counts and DNS status
	for i := range domains {
		emails, _ := s.repo.ListEmails(ctx, domains[i].Domain)
		domains[i].EmailCount = len(emails)

		leakCount := 0
		for _, e := range emails {
			leakCount += e.LeakCount
		}
		domains[i].LeakCount = leakCount

		dnsCheck, _ := s.repo.GetLatestDomainCheck(ctx, domains[i].Domain)
		domains[i].DNSCheck = dnsCheck
	}

	return domains, nil
}

// AddDomain adds a new domain and triggers initial DNS check
func (s *Service) AddDomain(ctx context.Context, domain string) (*entity.VigimailDomain, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Validate domain format
	if !strings.Contains(domain, ".") || len(domain) < 4 {
		return nil, fmt.Errorf("invalid domain format: %s", domain)
	}

	// Add to DB
	d, err := s.repo.AddDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Trigger initial DNS check asynchronously
	go func() {
		checkCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if check, err := s.CheckDomain(checkCtx, domain); err == nil {
			d.DNSCheck = check
		}
	}()

	slog.Info("[VIGIMAIL] Domain added", "domain", domain)
	return d, nil
}

// DeleteDomain removes a domain and its emails
func (s *Service) DeleteDomain(ctx context.Context, domain string) error {
	if err := s.repo.DeleteDomain(ctx, domain); err != nil {
		return err
	}
	slog.Info("[VIGIMAIL] Domain deleted", "domain", domain)
	return nil
}

// CheckDomain performs DNS configuration check for a domain
func (s *Service) CheckDomain(ctx context.Context, domain string) (*entity.DomainDNSCheck, error) {
	if s.dnsChecker == nil {
		return nil, fmt.Errorf("DNS checker not configured")
	}

	check, err := s.dnsChecker.CheckDomain(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("DNS check failed: %w", err)
	}

	// Save result
	if err := s.repo.SaveDomainCheck(ctx, check); err != nil {
		slog.Error("[VIGIMAIL] Failed to save DNS check", "domain", domain, "error", err)
	}

	return check, nil
}

// GetDomainDNS returns the latest DNS check for a domain
func (s *Service) GetDomainDNS(ctx context.Context, domain string) (*entity.DomainDNSCheck, error) {
	return s.repo.GetLatestDomainCheck(ctx, domain)
}

// ============================================
// Email Management
// ============================================

// ListEmails returns emails for a domain (or all if domain is empty)
func (s *Service) ListEmails(ctx context.Context, domain string) ([]entity.VigimailEmail, error) {
	if domain == "" {
		return s.repo.ListAllEmails(ctx)
	}
	return s.repo.ListEmails(ctx, domain)
}

// AddEmail adds an email and triggers initial leak check
func (s *Service) AddEmail(ctx context.Context, email string) (*entity.VigimailEmail, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	// Validate email format
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return nil, fmt.Errorf("invalid email format: %s", email)
	}

	// Add to DB
	e, err := s.repo.AddEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	// Trigger initial leak check asynchronously
	go func() {
		checkCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		s.CheckEmail(checkCtx, email)
	}()

	slog.Info("[VIGIMAIL] Email added", "email", email)
	return e, nil
}

// DeleteEmail removes an email from monitoring
func (s *Service) DeleteEmail(ctx context.Context, email string) error {
	if err := s.repo.DeleteEmail(ctx, email); err != nil {
		return err
	}
	slog.Info("[VIGIMAIL] Email deleted", "email", email)
	return nil
}

// CheckEmail checks an email for leaks using all configured providers
func (s *Service) CheckEmail(ctx context.Context, email string) ([]entity.VigimailLeak, error) {
	email = strings.ToLower(email)
	var allLeaks []entity.VigimailLeak

	// Check with HIBP
	if s.hibpClient != nil && s.hibpClient.IsConfigured() {
		leaks, err := s.hibpClient.CheckEmail(ctx, email)
		if err != nil {
			slog.Warn("[VIGIMAIL] HIBP check failed", "email", email, "error", err)
		} else {
			allLeaks = append(allLeaks, leaks...)
		}
	}

	// Check with LeakCheck
	if s.leakCheck != nil && s.leakCheck.IsConfigured() {
		leaks, err := s.leakCheck.CheckEmail(ctx, email)
		if err != nil {
			slog.Warn("[VIGIMAIL] LeakCheck check failed", "email", email, "error", err)
		} else {
			allLeaks = append(allLeaks, leaks...)
		}
	}

	// Deduplicate leaks by breach name
	uniqueLeaks := deduplicateLeaks(allLeaks)

	// Save leaks
	if len(uniqueLeaks) > 0 {
		if err := s.repo.SaveLeaks(ctx, uniqueLeaks); err != nil {
			slog.Error("[VIGIMAIL] Failed to save leaks", "email", email, "error", err)
		}
	}

	// Update email status
	status := "clean"
	if len(uniqueLeaks) > 0 {
		status = "leaked"
	}
	if err := s.repo.UpdateEmailStatus(ctx, email, status, len(uniqueLeaks)); err != nil {
		slog.Error("[VIGIMAIL] Failed to update email status", "email", email, "error", err)
	}

	slog.Info("[VIGIMAIL] Email checked", "email", email, "leaks", len(uniqueLeaks))
	return uniqueLeaks, nil
}

// GetEmailLeaks returns all leaks for an email
func (s *Service) GetEmailLeaks(ctx context.Context, email string) ([]entity.VigimailLeak, error) {
	return s.repo.GetLeaksForEmail(ctx, email)
}

// ============================================
// Bulk Operations
// ============================================

// CheckAll performs a full check of all emails and domains
func (s *Service) CheckAll(ctx context.Context) (*entity.VigimailCheckHistory, error) {
	startTime := time.Now()

	// Use a background context with extended timeout (5 minutes)
	// to prevent HTTP request cancellation from killing the checks
	checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	history := &entity.VigimailCheckHistory{
		CheckType: "full",
	}

	// Check all domains DNS
	domains, err := s.repo.ListDomains(checkCtx)
	if err == nil {
		for _, d := range domains {
			if _, err := s.CheckDomain(checkCtx, d.Domain); err != nil {
				history.DNSIssuesFound++
			}
			history.DomainsChecked++
		}
	}

	// Check all emails for leaks
	emails, err := s.repo.ListAllEmails(checkCtx)
	if err == nil {
		for _, e := range emails {
			leaks, err := s.CheckEmail(checkCtx, e.Email)
			if err != nil {
				slog.Warn("[VIGIMAIL] Check failed", "email", e.Email, "error", err)
			} else {
				history.LeaksFound += len(leaks)
			}
			history.EmailsChecked++
		}
	}

	history.DurationMS = int(time.Since(startTime).Milliseconds())
	history.Success = true
	history.CheckTime = time.Now()

	// Save history
	s.repo.SaveCheckHistory(checkCtx, history)

	// Update last check time
	s.mu.Lock()
	s.config.LastCheck = time.Now()
	s.mu.Unlock()
	s.repo.UpdateLastCheck(checkCtx, time.Now())

	slog.Info("[VIGIMAIL] Full check completed",
		"domains", history.DomainsChecked,
		"emails", history.EmailsChecked,
		"leaks", history.LeaksFound,
		"duration_ms", history.DurationMS)

	return history, nil
}

// GetStats returns aggregated statistics
func (s *Service) GetStats(ctx context.Context) (*entity.VigimailStats, error) {
	return s.repo.GetStats(ctx)
}

// ============================================
// Background Worker
// ============================================

type checkWorker struct {
	service  *Service
	interval time.Duration
	stopChan chan struct{}
	running  bool
	mu       sync.Mutex
}

// StartWorker starts the background check worker
func (s *Service) StartWorker() {
	s.mu.Lock()
	if s.workerRunning {
		s.mu.Unlock()
		return
	}

	interval := time.Duration(s.config.CheckIntervalHours) * time.Hour
	if interval < time.Hour {
		interval = 24 * time.Hour // Default to daily
	}

	s.worker = &checkWorker{
		service:  s,
		interval: interval,
		stopChan: make(chan struct{}),
	}
	s.workerRunning = true
	s.mu.Unlock()

	go s.worker.run()
	slog.Info("[VIGIMAIL] Worker started", "interval", interval)
}

// StopWorker stops the background worker
func (s *Service) StopWorker() {
	s.mu.Lock()
	if !s.workerRunning || s.worker == nil {
		s.mu.Unlock()
		return
	}

	close(s.worker.stopChan)
	s.workerRunning = false
	s.mu.Unlock()

	slog.Info("[VIGIMAIL] Worker stopped")
}

func (w *checkWorker) run() {
	w.mu.Lock()
	w.running = true
	w.mu.Unlock()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			slog.Info("[VIGIMAIL] Worker triggered check")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)

			// Cleanup orphan data first
			if leaksDeleted, err := w.service.CleanupOrphanData(ctx); err != nil {
				slog.Error("[VIGIMAIL] Cleanup failed", "error", err)
			} else if leaksDeleted > 0 {
				slog.Info("[VIGIMAIL] Cleaned up orphan data", "leaks_deleted", leaksDeleted)
			}

			// Run checks
			if _, err := w.service.CheckAll(ctx); err != nil {
				slog.Error("[VIGIMAIL] Worker check failed", "error", err)
			}
			cancel()

		case <-w.stopChan:
			w.mu.Lock()
			w.running = false
			w.mu.Unlock()
			return
		}
	}
}

// ============================================
// Helpers
// ============================================

func deduplicateLeaks(leaks []entity.VigimailLeak) []entity.VigimailLeak {
	seen := make(map[string]bool)
	result := make([]entity.VigimailLeak, 0)

	for _, leak := range leaks {
		key := leak.Email + "|" + leak.BreachName
		if !seen[key] {
			seen[key] = true
			result = append(result, leak)
		}
	}

	return result
}
