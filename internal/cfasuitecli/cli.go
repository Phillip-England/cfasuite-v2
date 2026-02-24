package cfasuitecli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/phillip-england/cfasuite/internal/apiapp"
	"github.com/phillip-england/cfasuite/internal/clientapp"
	"github.com/phillip-england/cfasuite/internal/envutil"
	"github.com/phillip-england/cfasuite/internal/security"
)

var ErrUsage = errors.New("usage")

func PrintUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, usageText())
}

func usageText() string {
	return strings.TrimSpace(`
CFA Suite CLI

Purpose:
  Self-contained CLI to bootstrap and run CFA Suite on a VPS.

Usage:
  cfasuite setup --admin-password <password> [--admin-username admin] [--env-file .env] [--force]
  cfasuite assets build
  cfasuite run api|client|all
  cfasuite help

First-time VPS bootstrap (Ubuntu/Debian):
  1) Install dependencies:
     sudo apt update
     sudo apt install -y git golang ca-certificates curl

  2) Clone and build:
     git clone <your-repo-url> cfasuite
     cd cfasuite
     go build -o bin/cfasuite ./cmd/cfasuite

  3) Generate .env:
     ./bin/cfasuite setup --admin-password 'REPLACE_WITH_STRONG_PASSWORD'

  4) Run app:
     ./bin/cfasuite run all

What run targets do:
  run api     Start API server only (default .env API_ADDR=:8080)
  run client  Build assets if needed, then start client server (default CLIENT_ADDR=:3000)
  run all     Build assets if needed, start API + client together

Notes:
  - The CLI auto-builds frontend assets and auto-installs Tailwind binary into ./bin when needed.
  - setup writes .env with sane defaults; rerun with --force to overwrite.
  - Open ports 8080 (API) and 3000 (client) on your VPS/firewall as needed.
`) + "\n"
}

func Execute(args []string) error {
	if len(args) < 1 || isHelpArg(args[0]) {
		return usageError()
	}

	switch args[0] {
	case "setup":
		return runSetup(args[1:])
	case "assets":
		return runAssets(args[1:])
	case "run":
		return runCommand(args[1:])
	case "help":
		return usageError()
	default:
		return usageError()
	}
}

func usageError() error {
	return fmt.Errorf("%w: cfasuite <setup|assets|run|help>", ErrUsage)
}

func isHelpArg(arg string) bool {
	switch strings.TrimSpace(strings.ToLower(arg)) {
	case "-h", "--help", "help":
		return true
	default:
		return false
	}
}

func runSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	adminUser := fs.String("admin-username", "admin", "initial admin username")
	adminPass := fs.String("admin-password", "", "initial admin password (min 12 chars)")
	envPath := fs.String("env-file", ".env", "path to .env file")
	force := fs.Bool("force", false, "overwrite existing env file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return usageError()
		}
		return err
	}

	if *adminPass == "" {
		return errors.New("--admin-password is required")
	}
	if _, err := security.HashPassword(*adminPass); err != nil {
		return fmt.Errorf("invalid admin password: %w", err)
	}

	values := map[string]string{
		"ADMIN_USERNAME": *adminUser,
		"ADMIN_PASSWORD": *adminPass,
		"AUTH_DB_PATH":   "data.db",
		"API_ADDR":       ":8080",
		"CLIENT_ADDR":    ":3000",
		"API_BASE_URL":   "http://localhost:8080",
	}

	if err := envutil.WriteDotEnv(*envPath, values, *force); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", *envPath)
	return nil
}

func runCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%w: missing run target: api | client | all", ErrUsage)
	}
	if isHelpArg(args[0]) {
		return usageError()
	}

	if err := envutil.LoadDotEnv(".env"); err != nil {
		return fmt.Errorf("load .env: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	switch args[0] {
	case "api":
		return runAPI(ctx)
	case "client":
		return runClient(ctx)
	case "all":
		return runAll(ctx)
	default:
		return fmt.Errorf("%w: unknown run target %q", ErrUsage, args[0])
	}
}

func runAPI(ctx context.Context) error {
	cfg := apiapp.DefaultConfigFromEnv()
	if err := ensureParentDirs(cfg.DBPath); err != nil {
		return err
	}
	if err := apiapp.Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func runClient(ctx context.Context) error {
	if err := ensureClientAssets(ctx); err != nil {
		return err
	}
	return runClientServer(ctx)
}

func runClientServer(ctx context.Context) error {
	cfg := clientapp.DefaultConfigFromEnv()
	if err := clientapp.Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func runAll(ctx context.Context) error {
	if err := ensureClientAssets(ctx); err != nil {
		return err
	}

	errCh := make(chan error, 2)

	go func() { errCh <- runAPI(ctx) }()
	go func() {
		time.Sleep(500 * time.Millisecond)
		errCh <- runClientServer(ctx)
	}()

	for i := 0; i < 2; i++ {
		err := <-errCh
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return nil
}

func ensureParentDirs(paths ...string) error {
	for _, p := range paths {
		dir := filepath.Dir(p)
		if dir == "." || dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	return nil
}
