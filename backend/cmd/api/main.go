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
	"github.com/kr1s57/vigilancex/internal/config"

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
				r.Get("/", handlers.NotImplemented)
				r.Get("/{id}", handlers.NotImplemented)
				r.Get("/timeline", handlers.NotImplemented)
				r.Get("/search", handlers.NotImplemented)
				r.Get("/export", handlers.NotImplemented)
			})

			// Stats
			r.Route("/stats", func(r chi.Router) {
				r.Get("/overview", handlers.NotImplemented)
				r.Get("/hourly", handlers.NotImplemented)
				r.Get("/daily", handlers.NotImplemented)
				r.Get("/by-ip", handlers.NotImplemented)
				r.Get("/by-rule", handlers.NotImplemented)
				r.Get("/by-category", handlers.NotImplemented)
				r.Get("/by-country", handlers.NotImplemented)
				r.Get("/trends", handlers.NotImplemented)
				r.Get("/top-attackers", handlers.NotImplemented)
				r.Get("/top-targets", handlers.NotImplemented)
			})

			// Geo
			r.Route("/geo", func(r chi.Router) {
				r.Get("/heatmap", handlers.NotImplemented)
				r.Get("/by-country", handlers.NotImplemented)
				r.Get("/lookup/{ip}", handlers.NotImplemented)
			})

			// Threats
			r.Route("/threats", func(r chi.Router) {
				r.Get("/", handlers.NotImplemented)
				r.Get("/score/{ip}", handlers.NotImplemented)
				r.Post("/refresh/{ip}", handlers.NotImplemented)
				r.Get("/categories", handlers.NotImplemented)
				r.Get("/campaigns", handlers.NotImplemented)
				r.Get("/apt", handlers.NotImplemented)
			})

			// Bans
			r.Route("/bans", func(r chi.Router) {
				r.Get("/", handlers.NotImplemented)
				r.Get("/{ip}", handlers.NotImplemented)
				r.Post("/", handlers.NotImplemented)
				r.Delete("/{ip}", handlers.NotImplemented)
				r.Put("/{ip}/extend", handlers.NotImplemented)
				r.Put("/{ip}/permanent", handlers.NotImplemented)
				r.Get("/history", handlers.NotImplemented)
				r.Get("/history/{ip}", handlers.NotImplemented)
				r.Get("/stats", handlers.NotImplemented)
				r.Post("/sync", handlers.NotImplemented)
			})

			// Whitelist
			r.Route("/whitelist", func(r chi.Router) {
				r.Get("/", handlers.NotImplemented)
				r.Post("/", handlers.NotImplemented)
				r.Delete("/{ip}", handlers.NotImplemented)
				r.Get("/check/{ip}", handlers.NotImplemented)
			})

			// Anomalies
			r.Route("/anomalies", func(r chi.Router) {
				r.Get("/", handlers.NotImplemented)
				r.Get("/spikes", handlers.NotImplemented)
				r.Get("/new-ips", handlers.NotImplemented)
				r.Get("/patterns", handlers.NotImplemented)
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

			// IPS
			r.Route("/ips", func(r chi.Router) {
				r.Get("/alerts", handlers.NotImplemented)
				r.Get("/signatures", handlers.NotImplemented)
				r.Get("/exploits", handlers.NotImplemented)
			})

			// System
			r.Route("/system", func(r chi.Router) {
				r.Get("/config", handlers.NotImplemented)
				r.Get("/sophos/status", handlers.NotImplemented)
				r.Post("/sophos/test", handlers.NotImplemented)
			})
		})
	})

	// WebSocket endpoint
	r.Get("/ws", handlers.NotImplemented)

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
