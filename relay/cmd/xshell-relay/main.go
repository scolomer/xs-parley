// Command xshell-relay is the blind relay of the xshell protocol (SPEC §6).
//
// Configuration: XSHELL_LISTEN (default ":8080").
package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/scolomer/omp-xshell/relay/internal/hub"
	"github.com/scolomer/omp-xshell/relay/internal/metrics"
	"github.com/scolomer/omp-xshell/relay/internal/ws"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	if err := run(log); err != nil {
		log.Error("arrêt sur erreur", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	listen := os.Getenv("XSHELL_LISTEN")
	if listen == "" {
		listen = ":8080"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	m := metrics.New()
	relay := ws.New(ws.Config{Hub: hub.New(m), Metrics: m, Log: log})
	mux := http.NewServeMux()
	mux.Handle("GET /ws", relay)
	mux.Handle("GET /metrics", m.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Info("relai démarré", "listen", listener.Addr().String())

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	log.Info("arrêt demandé")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Stop accepting first: hijacked WebSocket connections are not tracked by
	// the HTTP server and are closed by the relay itself.
	err = server.Shutdown(shutdownCtx)
	relay.Shutdown(shutdownCtx)
	return err
}
