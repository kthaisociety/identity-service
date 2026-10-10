package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/kthaisociety/identity-service/internal/config"
	"github.com/kthaisociety/identity-service/internal/database"
	"github.com/kthaisociety/identity-service/internal/handlers"
)

func main() {
	// Best effort: in a container the variables are set directly and there's no .env.
	_ = godotenv.Load()

	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	if err := database.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}

	deps := handlers.Deps{
		PingDB:        func(ctx context.Context) error { return database.Ping(ctx, db) },
		ServiceSecret: cfg.ServiceSecret,
	}

	// Two listeners (docs/adr/0003): public sign-in, and the internal API with admin rights.
	servers := []*http.Server{
		newServer("public", net.JoinHostPort(cfg.Host, cfg.PublicPort), handlers.NewPublicRouter(deps)),
		newServer("internal", net.JoinHostPort(cfg.Host, cfg.InternalPort), handlers.NewInternalRouter(deps)),
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown %s: %v", srv.Addr, err)
		}
	}
}

func newServer(name, addr string, handler http.Handler) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("identity-service %s listener on %s", name, addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	return srv
}
