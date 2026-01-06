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
	"github.com/kr1s57/vigilancex/internal/adapter/external/geolocation"
	"github.com/kr1s57/vigilancex/internal/adapter/external/sophos"
	"github.com/kr1s57/vigilancex/internal/adapter/external/threatintel"
	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/config"
	"github.com/kr1s57/vigilancex/internal/usecase/bans"
	"github.com/kr1s57/vigilancex/internal/usecase/events"
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

	// Initialize threat intelligence aggregator
	threatAggregator := threatintel.NewAggregator(threatintel.AggregatorConfig{
		AbuseIPDBKey:  cfg.ThreatIntel.AbuseIPDBKey,
		VirusTotalKey: cfg.ThreatIntel.VirusTotalKey,
		OTXKey:        cfg.ThreatIntel.AlienVaultKey,
		CacheTTL:      cfg.ThreatIntel.CacheTTL,
	})

	// Log configured providers
	providers := threatAggregator.GetConfiguredProviders()
	logger.Info("Threat Intelligence providers configured", "providers", providers)

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

	// Initialize services
	eventsService := events.NewService(eventsRepo, logger)
	threatsService := threats.NewService(threatsRepo, threatAggregator)
	bansService := bans.NewService(bansRepo, sophosClient)
	reportsService := reports.NewService(statsRepo, logger)

	// Initialize handlers
	eventsHandler := handlers.NewEventsHandler(eventsService)
	threatsHandler := handlers.NewThreatsHandler(threatsService)
	bansHandler := handlers.NewBansHandler(bansService)
	modsecHandler := handlers.NewModSecHandler(modsecService, modsecRepo)
	reportsHandler := handlers.NewReportsHandler(reportsService)

	// Initialize WebSocket hub
	wsHub := ws.NewHub()
	go wsHub.Run()
	logger.Info("WebSocket hub started")

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
		// Public routes
		r.Group(func(r chi.Router) {
			r.Post("/auth/login", handlers.NotImplemented)
			r.Post("/auth/logout", handlers.NotImplemented)
			r.Post("/auth/refresh", handlers.NotImplemented)
		})

		// Protected routes (TODO: add JWT middleware)
		r.Group(func(r chi.Router) {
			// Events
			r.Route("/events", func(r chi.Router) {
				r.Get("/", eventsHandler.ListEvents)
				r.Get("/hostnames", eventsHandler.GetHostnames)
				r.Get("/{id}", eventsHandler.GetEvent)
				r.Get("/timeline", eventsHandler.GetTimeline)
				r.Get("/search", eventsHandler.ListEvents)
				r.Get("/export", handlers.NotImplemented)
			})

			// Stats
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
			})

			// Geo
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

			// Whitelist
			r.Route("/whitelist", func(r chi.Router) {
				r.Get("/", bansHandler.ListWhitelist)
				r.Post("/", bansHandler.AddWhitelist)
				r.Delete("/{ip}", bansHandler.RemoveWhitelist)
				r.Get("/check/{ip}", handlers.NotImplemented)
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

			// WebSocket endpoint
			r.Get("/ws", wsHub.ServeWS)
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
	}

	logger.Info("Server stopped")
}
