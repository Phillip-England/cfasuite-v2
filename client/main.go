package main

import (
	"context"
	"errors"
	"log"
	"os/signal"
	"syscall"

	"github.com/phillip-england/cfasuite/internal/clientapp"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := clientapp.Run(ctx, clientapp.DefaultConfigFromEnv()); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
