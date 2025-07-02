package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel_gate/internal/server"
	"sentinel_gate/pkg/config"
	"sentinel_gate/pkg/logger"
	"sentinel_gate/pkg/telemetry"

	"go.uber.org/zap"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger, err := logger.NewLogger(cfg.Log.Level)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// Initialize telemetry
	shutdown, err := telemetry.Init(cfg.Telemetry)
	if err != nil {
		logger.Fatal("Failed to initialize telemetry", zap.Error(err))
	}
	defer shutdown()

	// Create and configure server
	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to create server", zap.Error(err))
	}

	// Start HTTP server
	httpServer := &http.Server{
		Addr:    cfg.Server.Port,
		Handler: srv.Handler(),
	}

	// Goroutine to start the server
	go func() {
		logger.Info("Starting Sentinel Gate API Gateway",
			zap.String("port", cfg.Server.Port),
			zap.String("environment", cfg.Environment))

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Erro ao iniciar servidor HTTP", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Fatal("Error shutting down server", zap.Error(err))
	}

	logger.Info("Server shut down successfully")
}
