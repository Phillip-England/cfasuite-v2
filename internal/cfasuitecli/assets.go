package cfasuitecli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ulikunitz/xz"
)

const (
	tailwindVersion = "v3.4.17"
	pdfcpuVersion   = "v0.11.1"
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

// pdfcpu binary management – mirrors the tailwind pattern.

func ensurePdfcpuBinary(ctx context.Context) (string, error) {
	localPath := localPdfcpuBinaryPath()
	if err := ensurePdfcpuDownload(ctx, localPath); err != nil {
		return "", err
	}
	return localPath, nil
}

func localPdfcpuBinaryPath() string {
	name := "pdfcpu"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join("bin", name)
}

func ensurePdfcpuDownload(ctx context.Context, destination string) error {
	if info, err := os.Stat(destination); err == nil {
		if info.Mode()&0o111 != 0 {
			return nil
		}
	}

	assetName, err := pdfcpuReleaseAssetName()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create bin directory: %w", err)
	}

	url := fmt.Sprintf("https://github.com/pdfcpu/pdfcpu/releases/download/%s/%s", pdfcpuVersion, assetName)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("prepare pdfcpu download request: %w", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("download pdfcpu: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download pdfcpu: unexpected status %s", response.Status)
	}

	if strings.HasSuffix(assetName, ".zip") {
		data, err := io.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("read pdfcpu zip: %w", err)
		}
		return extractPdfcpuFromZip(data, destination)
	}
	return extractPdfcpuFromTarXz(response.Body, destination)
}

func pdfcpuReleaseAssetName() (string, error) {
	version := strings.TrimPrefix(pdfcpuVersion, "v")
	var osName, archName, ext string
	switch runtime.GOOS {
	case "darwin":
		osName = "Darwin"
		ext = ".tar.xz"
	case "linux":
		osName = "Linux"
		ext = ".tar.xz"
	case "windows":
		osName = "Windows"
		ext = ".zip"
	default:
		return "", fmt.Errorf("unsupported platform for automatic pdfcpu install: %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	switch runtime.GOARCH {
	case "amd64":
		archName = "x86_64"
	case "arm64":
		// No Windows arm64 release; use x86_64 (runs under emulation).
		if runtime.GOOS == "windows" {
			archName = "x86_64"
		} else {
			archName = "arm64"
		}
	default:
		return "", fmt.Errorf("unsupported platform for automatic pdfcpu install: %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("pdfcpu_%s_%s_%s%s", version, osName, archName, ext), nil
}

func extractPdfcpuFromTarXz(r io.Reader, destination string) error {
	xzr, err := xz.NewReader(r)
	if err != nil {
		return fmt.Errorf("decompress pdfcpu archive: %w", err)
	}
	tr := tar.NewReader(xzr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read pdfcpu archive: %w", err)
		}
		if filepath.Base(hdr.Name) == "pdfcpu" && hdr.Typeflag != tar.TypeDir {
			return writePdfcpuBinary(tr, destination)
		}
	}
	return errors.New("pdfcpu binary not found in archive")
}

func extractPdfcpuFromZip(data []byte, destination string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("open pdfcpu zip: %w", err)
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == "pdfcpu.exe" && !f.FileInfo().IsDir() {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("open pdfcpu binary in zip: %w", err)
			}
			defer rc.Close()
			return writePdfcpuBinary(rc, destination)
		}
	}
	return errors.New("pdfcpu binary not found in zip")
}

func writePdfcpuBinary(r io.Reader, destination string) error {
	tmpPath := destination + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("create temporary pdfcpu binary: %w", err)
	}
	if _, err := io.Copy(file, r); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write pdfcpu binary: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary pdfcpu binary: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0o755); err != nil {
			return fmt.Errorf("mark pdfcpu binary executable: %w", err)
		}
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return fmt.Errorf("install pdfcpu binary: %w", err)
	}
	return nil
}
