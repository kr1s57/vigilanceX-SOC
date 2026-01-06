package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vigilancex/internal/config"
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
	logger.Info("Starting VIGILANCE X Detect2Ban Engine",
		"env", cfg.App.Env,
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// TODO: Initialize engine components
	// - ClickHouse connection for reading events
	// - Redis connection for state and deduplication
	// - Sophos client for ban actions
	// - Scenario loader (YAML)
	// - Event matcher
	// - Action executor

	// Start the detection loop
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Info("Detection loop stopped")
				return
			case <-ticker.C:
				// TODO: Implement detection loop
				// 1. Query recent events from ClickHouse
				// 2. Match against loaded scenarios
				// 3. Execute actions (ban, alert) for matches
				// 4. Update state in Redis
				logger.Debug("Detection tick - not yet implemented")
			}
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down Detect2Ban engine...")
	cancel()

	// Give goroutines time to clean up
	time.Sleep(2 * time.Second)

	logger.Info("Detect2Ban engine stopped")
}
