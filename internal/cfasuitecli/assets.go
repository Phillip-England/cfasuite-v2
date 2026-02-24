package cfasuitecli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const (
	tailwindVersion = "v3.4.17"
)

func runAssets(args []string) error {
	fs := flag.NewFlagSet("assets", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return usageError()
		}
		return err
	}
	if fs.NArg() == 1 && isHelpArg(fs.Arg(0)) {
		return usageError()
	}
	if fs.NArg() != 1 || fs.Arg(0) != "build" {
		return fmt.Errorf("%w: usage: cfasuite assets build", ErrUsage)
	}
	return ensureClientAssets(context.Background())
}

func ensureClientAssets(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(tailwindOutputPath()), 0o755); err != nil {
		return fmt.Errorf("create assets directory: %w", err)
	}

	tailwindPath, err := ensureTailwindBinary(ctx)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(
		ctx,
		tailwindPath,
		"-i", tailwindInputPath(),
		"-o", tailwindOutputPath(),
		"--config", tailwindConfigPath(),
		"--minify",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build tailwind css: %w", err)
	}
	return nil
}

func ensureTailwindBinary(ctx context.Context) (string, error) {
	localPath := localTailwindBinaryPath()
	if err := ensureTailwindDownload(ctx, localPath); err != nil {
		return "", err
	}
	return localPath, nil
}

func ensureTailwindDownload(ctx context.Context, destination string) error {
	if info, err := os.Stat(destination); err == nil {
		if info.Mode()&0o111 != 0 {
			return nil
		}
	}

	assetName, err := tailwindReleaseAssetName()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create bin directory: %w", err)
	}

	url := fmt.Sprintf("https://github.com/tailwindlabs/tailwindcss/releases/download/%s/%s", tailwindVersion, assetName)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("prepare tailwind download request: %w", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("download tailwindcss binary: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download tailwindcss binary: unexpected status %s", response.Status)
	}

	tmpPath := destination + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("create temporary tailwind binary: %w", err)
	}
	if _, err := io.Copy(file, response.Body); err != nil {
		_ = file.Close()
		return fmt.Errorf("write tailwind binary: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary tailwind binary: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0o755); err != nil {
			return fmt.Errorf("mark tailwind binary executable: %w", err)
		}
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return fmt.Errorf("install tailwind binary: %w", err)
	}

	return nil
}

func localTailwindBinaryPath() string {
	name := "tailwindcss"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join("bin", name)
}

func tailwindReleaseAssetName() (string, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		return "tailwindcss-macos-arm64", nil
	case "darwin/amd64":
		return "tailwindcss-macos-x64", nil
	case "linux/amd64":
		return "tailwindcss-linux-x64", nil
	case "linux/arm64":
		return "tailwindcss-linux-arm64", nil
	case "windows/amd64":
		return "tailwindcss-windows-x64.exe", nil
	case "windows/arm64":
		return "tailwindcss-windows-arm64.exe", nil
	default:
		return "", fmt.Errorf("unsupported platform for automatic tailwind install: %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

func tailwindInputPath() string {
	return filepath.Join("internal", "clientapp", "assets", "tailwind.input.css")
}

func tailwindOutputPath() string {
	return filepath.Join("internal", "clientapp", "assets", "app.css")
}

func tailwindConfigPath() string {
	return filepath.Join("internal", "clientapp", "tailwind.config.js")
}
