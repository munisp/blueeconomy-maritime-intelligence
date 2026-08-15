package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/server"
)

func main() {
	if err := run(); err != nil {
		log.Printf("maritime-intelligence: %v", err)
		os.Exit(1)
	}
}

func run() error {
	databaseURL := requiredEnv("DATABASE_URL")
	migrationPaths := requiredEnv("MIGRATION_PATH")
	port := requiredEnv("PORT")
	authMode := requiredEnv("AUTH_MODE")
	if authMode != server.AuthModeLoopbackTrustedProxy {
		return fmt.Errorf("AUTH_MODE must be %q until a verified Ministry edge is configured", server.AuthModeLoopbackTrustedProxy)
	}
	migrationPathsList := strings.Split(migrationPaths, ",")
	if len(migrationPathsList) == 0 {
		return errors.New("MIGRATION_PATH must contain at least one path")
	}
	migrations := make([][]byte, 0, len(migrationPathsList))
	for _, migrationPath := range migrationPathsList {
		migrationPath = strings.TrimSpace(migrationPath)
		if migrationPath == "" {
			return errors.New("MIGRATION_PATH contains an empty path")
		}
		migration, err := os.ReadFile(filepath.Clean(migrationPath))
		if err != nil {
			return fmt.Errorf("read migration %q: %w", migrationPath, err)
		}
		migrations = append(migrations, migration)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	store, err := incident.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	for index, migration := range migrations {
		if err := store.Exec(ctx, string(migration)); err != nil {
			return fmt.Errorf("apply migration %d: %w", index+1, err)
		}
	}
	httpServer := &http.Server{
		Addr: ":" + port, Handler: server.New(store, authMode), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	log.Printf("maritime-intelligence listening on :%s", port)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s must be set", name)
	}
	return value
}
