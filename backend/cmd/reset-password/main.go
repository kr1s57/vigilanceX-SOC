package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/kr1s57/vigilancex/internal/adapter/repository/clickhouse"
	"github.com/kr1s57/vigilancex/internal/config"
	"github.com/kr1s57/vigilancex/internal/usecase/auth"
)

func main() {
	// Get arguments
	if len(os.Args) < 3 {
		fmt.Println("VIGILANCE X - Admin Password Reset Tool")
		fmt.Println("")
		fmt.Println("Usage: reset-password <username> <new_password>")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  reset-password admin NewSecurePassword123!")
		fmt.Println("  reset-password admin MyN3wP@ssw0rd")
		fmt.Println("")
		fmt.Println("Requirements:")
		fmt.Println("  - Password must be at least 8 characters")
		fmt.Println("  - Run this command inside the vigilance_backend container")
		os.Exit(1)
	}

	username := os.Args[1]
	newPassword := os.Args[2]

	// Validate password length
	if len(newPassword) < 8 {
		fmt.Println("Error: Password must be at least 8 characters")
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Setup logger (minimal)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Initialize ClickHouse connection
	chConn, err := clickhouse.NewConnection(&cfg.ClickHouse, logger)
	if err != nil {
		fmt.Printf("Error connecting to ClickHouse: %v\n", err)
		os.Exit(1)
	}
	defer chConn.Close()

	// Initialize repository and service
	usersRepo := clickhouse.NewUsersRepository(chConn)
	authService := auth.NewService(usersRepo, cfg, logger)

	// Find user by username
	ctx := context.Background()
	user, err := usersRepo.GetByUsername(ctx, username)
	if err != nil {
		fmt.Printf("Error: User '%s' not found\n", username)
		os.Exit(1)
	}

	// Reset password
	err = authService.ResetPassword(ctx, user.ID, newPassword)
	if err != nil {
		fmt.Printf("Error resetting password: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Password for user '%s' has been reset successfully!\n", username)
	fmt.Println("")
	fmt.Println("You can now login with the new password.")
}
