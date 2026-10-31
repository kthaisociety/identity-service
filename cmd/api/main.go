package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/kthaisociety/identity-service/internal/config"
	"github.com/kthaisociety/identity-service/internal/database"
	"github.com/kthaisociety/identity-service/internal/googleauth"
	"github.com/kthaisociety/identity-service/internal/handlers"
	"github.com/kthaisociety/identity-service/internal/oidcprovider"
	"github.com/kthaisociety/identity-service/internal/safelog"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func main() {
	// The provider library uses slog.Default for its protocol errors. Keep
	// those records useful without printing raw error objects or request data.
	slog.SetDefault(safelog.New(os.Stderr))

	// Best effort: in a container the variables are set directly and there's no .env.
	_ = godotenv.Load()

	// Validate all required settings before starting either listener.
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Open Postgres and apply the versioned SQL schema.
	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	if err := database.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}
	store, cryptoKey, err := oidcprovider.NewStore(db, cfg)
	if err != nil {
		log.Fatal(err)
	}
	provider, err := oidcprovider.New(store, cryptoKey, cfg)
	if err != nil {
		log.Fatal(err)
	}
	google, err := googleauth.New(ctx, cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURI)
	if err != nil {
		log.Fatal("discovering Google OIDC provider: ", err)
	}

	// Both routers share the database but expose different capabilities.
	deps := handlers.Deps{
		// Health checks use the same database connection as sign-in.
		PingDB: func(ctx context.Context) error { return database.Ping(ctx, db) },
		// Only the internal router uses this secret for /v1 requests.
		ServiceSecret:   cfg.ServiceSecret,
		Provider:        provider,
		AuthStore:       store,
		Google:          google,
		AuthCallbackURL: op.AuthCallbackURL(provider),
		Issuer:          cfg.Issuer,
	}

	// Two listeners (docs/adr/0003): public sign-in and the internal API.
	servers := []*http.Server{
		// The public router handles browser sign-in and OIDC endpoints.
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
	// Run each listener until shutdown.
	go func() {
		log.Printf("identity-service %s listener on %s", name, addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	return srv
}
