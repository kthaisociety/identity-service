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

	// Loads the config using the strongly typed Config struct
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Open a reference to the DB via Gorm.
	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	// Applies any needed migrations
	if err := database.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}

	// Dependency injection so that HTTP routers can do their job
	deps := handlers.Deps{
		// A function that allows the router check the health of the DB.
		PingDB: func(ctx context.Context) error { return database.Ping(ctx, db) },
		// The identity-service secret is added here so that internal routers
		// can use it to verify it against the incoming X-Service-Secret header on any request to /v1/*
		ServiceSecret: cfg.ServiceSecret,
	}

	// Two listeners (docs/adr/0003): public sign-in, and the internal API with admin rights.
	// Starts two independent HTTP servers running at the same in
	servers := []*http.Server{
		// The internal router contains the routes for browsers, soon /authorize /token etc.
		newServer("public", net.JoinHostPort(cfg.Host, cfg.PublicPort), handlers.NewPublicRouter(deps)),
		// Internal route is intended for backend services (/v1/*) protected by the secret header.
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
	// Runs as a background go routine (thread)
	go func() {
		log.Printf("identity-service %s listener on %s", name, addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	return srv
}
