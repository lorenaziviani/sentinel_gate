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
	// Carregar configurações
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Erro ao carregar configurações: %v", err)
	}

	// Inicializar logger
	logger, err := logger.NewLogger(cfg.Log.Level)
	if err != nil {
		log.Fatalf("Erro ao inicializar logger: %v", err)
	}
	defer logger.Sync()

	// Inicializar telemetria
	shutdown, err := telemetry.Init(cfg.Telemetry)
	if err != nil {
		logger.Fatal("Erro ao inicializar telemetria", zap.Error(err))
	}
	defer shutdown()

	// Criar e configurar servidor
	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Fatal("Erro ao criar servidor", zap.Error(err))
	}

	// Iniciar servidor HTTP
	httpServer := &http.Server{
		Addr:    cfg.Server.Port,
		Handler: srv.Handler(),
	}

	// Goroutine para iniciar o servidor
	go func() {
		logger.Info("Iniciando Sentinel Gate API Gateway",
			zap.String("port", cfg.Server.Port),
			zap.String("environment", cfg.Environment))

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Erro ao iniciar servidor HTTP", zap.Error(err))
		}
	}()

	// Aguardar sinal de interrupção
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Desligando servidor...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Fatal("Erro no shutdown do servidor", zap.Error(err))
	}

	logger.Info("Servidor desligado com sucesso")
}
