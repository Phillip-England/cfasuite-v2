package cfasuitecli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/phillip-england/cfasuite/internal/apiapp"
	"github.com/phillip-england/cfasuite/internal/clientapp"
	"github.com/phillip-england/cfasuite/internal/envutil"
	"github.com/phillip-england/cfasuite/internal/security"
)

var ErrUsage = errors.New("usage")

func Execute(args []string) error {
	if len(args) < 1 {
		return usageError()
	}

	switch args[0] {
	case "setup":
		return runSetup(args[1:])
	case "run":
		return runCommand(args[1:])
	default:
		return usageError()
	}
}

func usageError() error {
	return fmt.Errorf("%w: cfasuite <setup|run> [...]", ErrUsage)
}

func runSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	adminUser := fs.String("admin-username", "admin", "initial admin username")
	adminPass := fs.String("admin-password", "", "initial admin password (min 12 chars)")
	envPath := fs.String("env-file", ".env", "path to .env file")
	force := fs.Bool("force", false, "overwrite existing env file")
	if err := fs.Parse(args); err != nil {
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
		return errors.New("missing run target: api | client | all")
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
		return fmt.Errorf("unknown run target %q", args[0])
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
	cfg := clientapp.DefaultConfigFromEnv()
	if err := clientapp.Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func runAll(ctx context.Context) error {
	errCh := make(chan error, 2)

	go func() { errCh <- runAPI(ctx) }()
	go func() {
		time.Sleep(500 * time.Millisecond)
		errCh <- runClient(ctx)
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
