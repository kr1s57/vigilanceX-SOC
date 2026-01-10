package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kr1s57/vigilancex/internal/adapter/controller/http/handlers"
	"github.com/kr1s57/vigilancex/internal/adapter/controller/http/middleware"
	"github.com/kr1s57/vigilancex/internal/adapter/controller/ws"
	"github.com/kr1s57/vigilancex/internal/adapter/external/blocklist"
	"github.com/kr1s57/vigilancex/internal/adapter/external/geoip"
	"github.com/kr1s57/vigilancex/internal/adapter/external/geolocation"
	"github.com/kr1s57/vigilancex/internal/adapter/external/sophos"
	"github.com/kr1s57/vigilancex/internal/adapter/external/threatintel"
	sophosparser "github.com/kr1s57/vigilancex/internal/adapter/parser/sophos"
	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/config"
	"github.com/kr1s57/vigilancex/internal/license" // v2.9: License system
	"github.com/kr1s57/vigilancex/internal/usecase/auth"
	"github.com/kr1s57/vigilancex/internal/usecase/bans"
	"github.com/kr1s57/vigilancex/internal/usecase/blocklists"
	"github.com/kr1s57/vigilancex/internal/usecase/events"
	"github.com/kr1s57/vigilancex/internal/usecase/geoblocking"
	"github.com/kr1s57/vigilancex/internal/usecase/modsec"
	"github.com/kr1s57/vigilancex/internal/usecase/reports"
	"github.com/kr1s57/vigilancex/internal/usecase/threats"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Setup logger
	logger := config.SetupLogger(cfg)
	logger.Info("Starting VIGILANCE X API",
		"env", cfg.App.Env,
		"port", cfg.App.Port,
	)

	// Initialize ClickHouse connection
	chConn, err := clickhouse.NewConnection(&cfg.ClickHouse, logger)
	if err != nil {
		logger.Error("Failed to connect to ClickHouse", "error", err)
		os.Exit(1)
	}
	defer chConn.Close()

	// Initialize repositories
	eventsRepo := clickhouse.NewEventsRepository(chConn, logger)
	threatsRepo := clickhouse.NewThreatsRepository(chConn)
	bansRepo := clickhouse.NewBansRepository(chConn)
	modsecRepo := clickhouse.NewModSecRepository(chConn, logger)
	statsRepo := clickhouse.NewStatsRepository(chConn.Conn(), logger)
	blocklistRepo := clickhouse.NewBlocklistRepository(chConn)
	geoblockingRepo := clickhouse.NewGeoblockingRepository(chConn) // v2.0: Geoblocking
	usersRepo := clickhouse.NewUsersRepository(chConn)             // v2.6: Authentication

	// v3.0: Initialize License Client with Firewall Binding
	var licenseClient *license.Client
	var heartbeatService *license.HeartbeatService
	if cfg.License.Enabled {
		var err error
		// v3.0: Create ClickHouse adapter for license system (wraps QueryRow to implement DBQuerier)
		chAdapter := license.NewClickHouseAdapter(func(ctx context.Context, query string, args ...interface{}) license.RowScanner {
			return chConn.QueryRow(ctx, query, args...)
		})

		// v3.0: Use NewClientWithFirewall for secure VM+Firewall binding
		licenseClient, err = license.NewClientWithFirewall(context.Background(), license.LicenseConfig{
			ServerURL:    cfg.License.ServerURL,
			LicenseKey:   cfg.License.LicenseKey,
			HeartbeatInt: cfg.License.HeartbeatInt,
			GracePeriod:  cfg.License.GracePeriod,
			Enabled:      cfg.License.Enabled,
			StorePath:    cfg.License.StorePath,
			Database:     cfg.ClickHouse.Database,
			DBConnection: chAdapter, // Pass ClickHouse adapter for firewall detection
		})
		if err != nil {
			logger.Error("Failed to initialize license client", "error", err)
			// Continue without license (will show unlicensed)
		} else {
			// Try to load persisted license
			if err := licenseClient.LoadFromStore(); err != nil {
				logger.Info("No persisted license found, activation required")
			}

			// Auto-activate if license key provided
			if cfg.License.LicenseKey != "" && !licenseClient.IsLicensed() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := licenseClient.Activate(ctx, cfg.License.LicenseKey); err != nil {
					logger.Warn("Auto-activation failed", "error", err)
				}
				cancel()
			}

			// Start heartbeat service
			heartbeatService = license.NewHeartbeatService(licenseClient, cfg.License.HeartbeatInt)
			heartbeatService.Start()

			logger.Info("License system initialized",
				"server", cfg.License.ServerURL,
				"licensed", licenseClient.IsLicensed())
		}
	} else {
		logger.Info("License system disabled")
	}

	// Initialize threat intelligence aggregator (v2.9: with proxy support)
	var threatAggregator *threatintel.Aggregator
	if cfg.OSINTProxy.Enabled && licenseClient != nil && licenseClient.IsLicensed() {
		// v2.9: Use OSINT proxy mode - queries go through license server
		proxyClient := threatintel.NewOSINTProxyClient(threatintel.ProxyConfig{
			ServerURL:  cfg.OSINTProxy.ServerURL,
			LicenseKey: licenseClient.GetLicenseKey(),
			HardwareID: licenseClient.GetHardwareID(),
			Timeout:    cfg.OSINTProxy.Timeout,
			RateLimit:  cfg.OSINTProxy.RateLimit,
		})
		threatAggregator = threatintel.NewAggregatorWithProxy(proxyClient, cfg.ThreatIntel.CacheTTL)
		logger.Info("OSINT Proxy mode enabled", "server", cfg.OSINTProxy.ServerURL)
	} else {
		// Local providers mode (v2.9.6: 11 providers with cascade tiers)
		threatAggregator = threatintel.NewAggregator(threatintel.AggregatorConfig{
			// Tier 2 providers (moderate limits)
			AbuseIPDBKey: cfg.ThreatIntel.AbuseIPDBKey,
			GreyNoiseKey: cfg.ThreatIntel.GreyNoiseKey,
			CrowdSecKey:  cfg.ThreatIntel.CrowdSecKey, // v2.9.6: CrowdSec CTI (50/day)
			// Tier 3 providers (limited)
			VirusTotalKey: cfg.ThreatIntel.VirusTotalKey,
			CriminalIPKey: cfg.ThreatIntel.CriminalIPKey,
			PulsediveKey:  cfg.ThreatIntel.PulsediveKey,
			// Tier 1: OTX needs key, others (IPSum, ThreatFox, URLhaus, ShodanIDB) are free
			OTXKey: cfg.ThreatIntel.AlienVaultKey,
			// Cache settings
			CacheTTL: cfg.ThreatIntel.CacheTTL,
			// v2.9.5: Cascade configuration
			CascadeConfig: &threatintel.CascadeConfig{
				EnableCascade:  cfg.ThreatIntel.CascadeEnabled,
				Tier2Threshold: cfg.ThreatIntel.Tier2Threshold,
				Tier3Threshold: cfg.ThreatIntel.Tier3Threshold,
			},
		})
	}

	// Log configured providers
	providers := threatAggregator.GetConfiguredProviders()
	logger.Info("Threat Intelligence providers configured",
		"providers", providers,
		"count", len(providers),
		"proxy_mode", threatAggregator.IsProxyMode(),
		"cascade_enabled", cfg.ThreatIntel.CascadeEnabled,
		"tier2_threshold", cfg.ThreatIntel.Tier2Threshold,
		"tier3_threshold", cfg.ThreatIntel.Tier3Threshold)

	// Initialize Sophos XGS client
	var sophosClient *sophos.Client
	if cfg.Sophos.Host != "" && cfg.Sophos.Password != "" {
		sophosClient = sophos.NewClient(sophos.Config{
			Host:       cfg.Sophos.Host,
			Port:       cfg.Sophos.Port,
			Username:   cfg.Sophos.User,
			Password:   cfg.Sophos.Password,
			GroupName:  cfg.Sophos.BanGroup,
			SkipVerify: true,
			Timeout:    cfg.Sophos.Timeout,
		})
		logger.Info("Sophos XGS client configured", "host", cfg.Sophos.Host, "port", cfg.Sophos.Port)
	} else {
		logger.Warn("Sophos XGS client not configured - XGS sync disabled")
	}

	// Initialize geolocation service
	geoService := geolocation.NewService(chConn.Conn(), logger)
	logger.Info("Geolocation service initialized")

	// Initialize GeoIP client for geoblocking (v2.0)
	geoIPClient := geoip.NewClient(geoip.Config{
		CacheTTL:     24 * time.Hour,
		MaxCacheSize: 10000,
		Timeout:      10 * time.Second,
	})
	logger.Info("GeoIP client initialized for geoblocking v2.0")

	// Initialize Feed Ingester for blocklist synchronization (v1.6)
	feedIngester := blocklist.NewFeedIngester(blocklistRepo, blocklist.IngesterConfig{
		HTTPTimeout:     30 * time.Second,
		MaxConcurrent:   3,
		DefaultInterval: 1 * time.Hour,
	})
	logger.Info("Feed Ingester initialized", "feeds", len(blocklist.GetEnabledFeeds()))

	// Initialize ModSec sync service (SSH-based log correlation)
	var modsecService *modsec.Service
	if cfg.SophosSSH.Host != "" {
		modsecService = modsec.NewService(cfg.SophosSSH, chConn.Conn(), geoService, logger)
		// Start background sync
		go modsecService.Start(context.Background())
		logger.Info("ModSec sync service started", "host", cfg.SophosSSH.Host, "interval", cfg.SophosSSH.SyncInterval)

		// Start monthly geolocation refresh (runs on 1st of each month)
		go func() {
			for {
				now := time.Now()
				// Calculate next 1st of month at 3am
				nextMonth := time.Date(now.Year(), now.Month()+1, 1, 3, 0, 0, 0, now.Location())
				time.Sleep(time.Until(nextMonth))

				logger.Info("Starting monthly geolocation refresh")
				refreshed, err := modsecService.RefreshGeolocation(context.Background())
				if err != nil {
					logger.Error("Monthly geolocation refresh failed", "error", err)
				} else {
					logger.Info("Monthly geolocation refresh completed", "refreshed", refreshed)
				}
			}
		}()
	} else {
		logger.Warn("ModSec sync service not configured - SSH host not set")
	}

	// v3.1: Initialize Sophos XGS Parser (XML-based decoders and rules)
	var xgsParser *sophosparser.Parser
	scenariosDir := "./scenarios"
	if _, err := os.Stat(scenariosDir); err == nil {
		xgsParser = sophosparser.New()
		if err := xgsParser.LoadFromDir(scenariosDir); err != nil {
			logger.Warn("Failed to load Sophos XGS parser", "error", err, "dir", scenariosDir)
		} else {
			stats := xgsParser.GetStats()
			logger.Info("Sophos XGS Parser initialized",
				"fields", stats.TotalFieldsLoaded,
				"rules", stats.TotalRulesLoaded,
				"mitre_techniques", len(xgsParser.GetMitreCoverage()))
		}
	} else {
		logger.Info("Sophos XGS Parser not configured - scenarios directory not found", "dir", scenariosDir)
	}

	// Initialize services
	eventsService := events.NewService(eventsRepo, logger)
	eventsService.SetGeoProvider(&geoProviderAdapter{geoService: geoService})
	threatsService := threats.NewService(threatsRepo, threatAggregator)
	bansService := bans.NewService(bansRepo, sophosClient)
	reportsService := reports.NewService(statsRepo, logger)
	blocklistsService := blocklists.NewService(feedIngester)
	geoblockingService := geoblocking.NewService(geoblockingRepo, geoIPClient) // v2.0: Geoblocking
	authService := auth.NewService(usersRepo, cfg, logger)                     // v2.6: Authentication

	// Ensure default admin user exists (v2.6)
	if err := authService.EnsureDefaultAdmin(context.Background()); err != nil {
		logger.Error("Failed to ensure default admin user", "error", err)
		os.Exit(1)
	}

	// Initialize handlers
	eventsHandler := handlers.NewEventsHandler(eventsService)
	threatsHandler := handlers.NewThreatsHandler(threatsService)
	threatsHandler.SetBlocklistsService(blocklistsService) // v1.6: Combined risk assessment
	bansHandler := handlers.NewBansHandler(bansService)
	modsecHandler := handlers.NewModSecHandler(modsecService, modsecRepo)
	reportsHandler := handlers.NewReportsHandler(reportsService)
	blocklistsHandler := handlers.NewBlocklistsHandler(blocklistsService)
	geoblockingHandler := handlers.NewGeoblockingHandler(geoblockingService) // v2.0: Geoblocking
	authHandler := handlers.NewAuthHandler(authService, logger)              // v2.6: Authentication
	usersHandler := handlers.NewUsersHandler(authService, logger)            // v2.6: User management
	licenseHandler := handlers.NewLicenseHandler(licenseClient)              // v2.9: License management
	parserHandler := handlers.NewParserHandler(xgsParser)                    // v3.1: XGS Parser

	// Initialize WebSocket hub
	wsHub := ws.NewHub()
	go wsHub.Run()
	logger.Info("WebSocket hub started")

	// Start Feed Ingester for automatic blocklist synchronization
	go blocklistsService.Start(context.Background())
	logger.Info("Blocklist Feed Ingester started")

	// Create router
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(middleware.Logger(logger))
	r.Use(chimw.Recoverer)
	r.Use(chimw.Compress(5))

	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:5173", "https://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Rate limiting
	r.Use(httprate.LimitByIP(100, time.Minute))

	// Health check (no auth required)
	r.Get("/health", handlers.HealthCheck(cfg))

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public routes (no auth required)
		r.Group(func(r chi.Router) {
			r.Post("/auth/login", authHandler.Login)
			// v2.9: License endpoints (public - needed before activation)
			r.Get("/license/status", licenseHandler.GetStatus)
			// v3.0: Rate limit license activation to prevent brute-force (5 attempts per hour per IP)
			r.With(httprate.Limit(5, time.Hour, httprate.WithKeyFuncs(httprate.KeyByIP))).
				Post("/license/activate", licenseHandler.Activate)
			// v3.2: Fresh Deploy endpoints (public - rate limited)
			r.With(httprate.Limit(5, time.Hour, httprate.WithKeyFuncs(httprate.KeyByIP))).
				Post("/license/fresh-deploy", licenseHandler.FreshDeploy)
		})

		// ==============================================
		// FREE ROUTES (Auth only, no license required)
		// Dashboard, Events, Syslog, basic stats
		// ==============================================
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(authService))

			// Auth endpoints (authenticated users)
			r.Post("/auth/logout", authHandler.Logout)
			r.Get("/auth/me", authHandler.Me)
			r.Post("/auth/change-password", authHandler.ChangePassword)

			// v3.2: License management endpoints (authenticated, no license required)
			r.Post("/license/ask-pro", licenseHandler.AskProLicense)
			r.Post("/license/sync-firewall", licenseHandler.SyncFirewall)

			// Events (free - core dashboard functionality)
			r.Route("/events", func(r chi.Router) {
				r.Get("/", eventsHandler.ListEvents)
				r.Get("/hostnames", eventsHandler.GetHostnames)
				r.Get("/{id}", eventsHandler.GetEvent)
				r.Get("/timeline", eventsHandler.GetTimeline)
				r.Get("/search", eventsHandler.ListEvents)
				r.Get("/export", handlers.NotImplemented)
			})

			// Stats (free - basic dashboard stats)
			r.Route("/stats", func(r chi.Router) {
				r.Get("/overview", eventsHandler.GetOverview)
				r.Get("/hourly", handlers.NotImplemented)
				r.Get("/daily", handlers.NotImplemented)
				r.Get("/by-ip", handlers.NotImplemented)
				r.Get("/by-rule", handlers.NotImplemented)
				r.Get("/by-category", handlers.NotImplemented)
				r.Get("/by-country", handlers.NotImplemented)
				r.Get("/trends", handlers.NotImplemented)
				r.Get("/top-attackers", eventsHandler.GetTopAttackers)
				r.Get("/top-targets", eventsHandler.GetTopTargets)
				r.Get("/zone-traffic", eventsHandler.GetZoneTraffic) // v3.1: XGS Zone Traffic Flow
			})

			// Status endpoints (free - syslog status)
			r.Route("/status", func(r chi.Router) {
				r.Get("/syslog", eventsHandler.GetSyslogStatus)
			})

			// Alerts endpoints (free - critical alerts)
			r.Route("/alerts", func(r chi.Router) {
				r.Get("/critical", eventsHandler.GetCriticalAlerts)
			})

			// WebSocket endpoint (free - real-time updates)
			r.Get("/ws", wsHub.ServeWS)
		})

		// ==============================================
		// LICENSED ROUTES (Auth + License required)
		// OSINT, Bans, Whitelist, Geoblocking, Reports...
		// ==============================================
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(authService))
			// v2.9: Add license middleware for premium features
			if cfg.License.Enabled {
				r.Use(middleware.RequireLicense(licenseClient))
			}

			// Admin-only routes (v2.6)
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireAdmin())
				r.Route("/users", func(r chi.Router) {
					r.Get("/", usersHandler.List)
					r.Post("/", usersHandler.Create)
					r.Get("/{id}", usersHandler.Get)
					r.Put("/{id}", usersHandler.Update)
					r.Delete("/{id}", usersHandler.Delete)
					r.Post("/{id}/reset-password", usersHandler.ResetPassword)
				})
				// v2.9: License admin routes
				r.Get("/license/info", licenseHandler.GetInfo)
				r.Post("/license/validate", licenseHandler.ForceValidate)
			})

			// Geo (licensed - heatmap and geo features)
			r.Route("/geo", func(r chi.Router) {
				r.Get("/heatmap", eventsHandler.GetGeoHeatmap)
				r.Get("/by-country", handlers.NotImplemented)
				r.Get("/lookup/{ip}", handlers.NotImplemented)
			})

			// Threats
			r.Route("/threats", func(r chi.Router) {
				r.Get("/", threatsHandler.GetTopThreats)
				r.Get("/stats", threatsHandler.GetStats)
				r.Get("/providers", threatsHandler.GetProviders)
				r.Get("/check/{ip}", threatsHandler.CheckIP)
				r.Get("/score/{ip}", threatsHandler.GetStoredScore)
				r.Get("/should-ban/{ip}", threatsHandler.ShouldBan)
				r.Get("/risk/{ip}", threatsHandler.RiskAssessment) // v1.6: Combined threat+blocklist risk
				r.Get("/level/{level}", threatsHandler.GetThreatsByLevel)
				r.Post("/batch", threatsHandler.BatchCheck)
				r.Post("/cache/clear", threatsHandler.ClearCache)
			})

			// Bans
			r.Route("/bans", func(r chi.Router) {
				r.Get("/", bansHandler.List)
				r.Get("/stats", bansHandler.Stats)
				r.Get("/xgs-status", bansHandler.XGSStatus)
				r.Post("/", bansHandler.Create)
				r.Post("/sync", bansHandler.Sync)
				r.Get("/{ip}", bansHandler.Get)
				r.Delete("/{ip}", bansHandler.Delete)
				r.Post("/{ip}/extend", bansHandler.Extend)
				r.Post("/{ip}/permanent", bansHandler.MakePermanent)
				r.Get("/{ip}/history", bansHandler.History)
			})

			// Whitelist (v2.0 with soft whitelist support)
			r.Route("/whitelist", func(r chi.Router) {
				r.Get("/", bansHandler.ListWhitelist)
				r.Get("/stats", bansHandler.WhitelistStats)
				r.Get("/check/{ip}", bansHandler.CheckWhitelist)
				r.Post("/", bansHandler.AddWhitelist)
				r.Put("/{ip}", bansHandler.UpdateWhitelist)
				r.Delete("/{ip}", bansHandler.RemoveWhitelist)
			})

			// Blocklists (v1.6 - Feed Ingester)
			r.Route("/blocklists", func(r chi.Router) {
				r.Get("/stats", blocklistsHandler.GetStats)
				r.Get("/feeds", blocklistsHandler.GetFeeds)
				r.Get("/feeds/configured", blocklistsHandler.GetConfiguredFeeds)
				r.Post("/sync", blocklistsHandler.SyncAll)
				r.Post("/feeds/{name}/sync", blocklistsHandler.SyncFeed)
				r.Get("/check/{ip}", blocklistsHandler.CheckIP)
				r.Get("/high-risk", blocklistsHandler.GetHighRiskIPs)
			})

			// Geoblocking (v2.0 - Country/ASN blocking)
			r.Route("/geoblocking", func(r chi.Router) {
				// Rules management
				r.Get("/rules", geoblockingHandler.ListRules)
				r.Post("/rules", geoblockingHandler.CreateRule)
				r.Put("/rules/{id}", geoblockingHandler.UpdateRule)
				r.Delete("/rules/{id}", geoblockingHandler.DeleteRule)
				// Stats and info
				r.Get("/stats", geoblockingHandler.GetStats)
				// IP checks
				r.Get("/check/{ip}", geoblockingHandler.CheckIP)
				r.Get("/lookup/{ip}", geoblockingHandler.LookupGeo)
				// Country lists
				r.Get("/countries/blocked", geoblockingHandler.GetBlockedCountries)
				r.Get("/countries/watched", geoblockingHandler.GetWatchedCountries)
				r.Get("/countries/high-risk", geoblockingHandler.GetHighRiskCountries)
				// Cache management
				r.Post("/cache/refresh", geoblockingHandler.RefreshRulesCache)
			})

			// Anomalies
			r.Route("/anomalies", func(r chi.Router) {
				r.Get("/", handlers.StubAnomaliesList)
				r.Get("/spikes", handlers.StubAnomaliesList)
				r.Get("/new-ips", handlers.StubAnomaliesList)
				r.Get("/patterns", handlers.StubAnomaliesList)
				r.Put("/{id}/acknowledge", handlers.NotImplemented)
			})

			// Network
			r.Route("/network", func(r chi.Router) {
				r.Get("/connections", handlers.NotImplemented)
				r.Get("/protocols", handlers.NotImplemented)
				r.Get("/ports", handlers.NotImplemented)
				r.Get("/interfaces", handlers.NotImplemented)
			})

			// VPN
			r.Route("/vpn", func(r chi.Router) {
				r.Get("/sessions", handlers.NotImplemented)
				r.Get("/history", handlers.NotImplemented)
				r.Get("/users", handlers.NotImplemented)
				r.Get("/failures", handlers.NotImplemented)
			})

			// WAF
			r.Route("/waf", func(r chi.Router) {
				r.Get("/attacks", handlers.NotImplemented)
				r.Get("/rules", handlers.NotImplemented)
				r.Get("/payloads", handlers.NotImplemented)
			})

			// ModSec
			r.Route("/modsec", func(r chi.Router) {
				r.Get("/stats", modsecHandler.GetStats)
				r.Post("/sync", modsecHandler.SyncNow)
				r.Get("/test", modsecHandler.TestConnection)
				r.Get("/logs", modsecHandler.GetLogs)
				r.Get("/logs/grouped", modsecHandler.GetGroupedLogs)
				r.Get("/hostnames", modsecHandler.GetHostnames)
				r.Get("/rules/stats", modsecHandler.GetRuleStats)
				r.Get("/attacks/stats", modsecHandler.GetAttackTypeStats)
			})

			// IPS
			r.Route("/ips", func(r chi.Router) {
				r.Get("/alerts", handlers.NotImplemented)
				r.Get("/signatures", handlers.NotImplemented)
				r.Get("/exploits", handlers.NotImplemented)
			})

			// Reports
			r.Route("/reports", func(r chi.Router) {
				r.Get("/stats", reportsHandler.GetDBStats)
				r.Get("/generate", reportsHandler.GenerateReport)
				r.Post("/generate", reportsHandler.GenerateReport)
				r.Get("/preview", reportsHandler.PreviewReport)
			})

			// System
			r.Route("/system", func(r chi.Router) {
				r.Get("/config", handlers.NotImplemented)
				r.Get("/sophos/status", handlers.NotImplemented)
				r.Post("/sophos/test", handlers.NotImplemented)
			})

			// Config management (v2.3 - Plugin configuration)
			r.Route("/config", func(r chi.Router) {
				configHandler := handlers.NewConfigHandler()
				r.Post("/test", configHandler.TestConfig)
				r.Post("/save", configHandler.SaveConfig)
				r.Get("/", configHandler.GetConfig)
				// System whitelist (v2.3 - Protected IPs)
				r.Get("/system-whitelist", configHandler.GetSystemWhitelist)
				r.Get("/system-whitelist/check/*", configHandler.CheckSystemWhitelist)
			})

			// Parser (v3.1 - Sophos XGS Parser with XML decoders/rules)
			r.Route("/parser", func(r chi.Router) {
				r.Get("/stats", parserHandler.GetStats)
				r.Get("/fields", parserHandler.GetFields)
				r.Get("/rules", parserHandler.GetRules)
				r.Get("/mitre", parserHandler.GetMitreCoverage)
				r.Post("/test", parserHandler.TestParse)
			})
		})
	})

	// WebSocket endpoint (also at root for easier access)
	r.Get("/ws", wsHub.ServeWS)

	// Create server
	addr := fmt.Sprintf("%s:%d", cfg.App.Host, cfg.App.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("HTTP server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// v2.9: Stop heartbeat service
	if heartbeatService != nil {
		heartbeatService.Stop()
		logger.Info("License heartbeat service stopped")
	}

	// Stop Feed Ingester
	blocklistsService.Stop()
	logger.Info("Feed Ingester stopped")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
	}

	logger.Info("Server stopped")
}

// geoProviderAdapter adapts the geolocation.Service to the events.GeoProvider interface
type geoProviderAdapter struct {
	geoService *geolocation.Service
}

func (a *geoProviderAdapter) LookupBatch(ctx context.Context, ips []string) (map[string]*events.GeoInfo, error) {
	geoData, err := a.geoService.LookupBatch(ctx, ips)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*events.GeoInfo)
	for ip, info := range geoData {
		if info != nil {
			result[ip] = &events.GeoInfo{
				IP:          info.IP,
				CountryCode: info.CountryCode,
				CountryName: info.CountryName,
			}
		}
	}
	return result, nil
}
