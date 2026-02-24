package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/phillip-england/cfasuite/internal/cfasuitecli"
)

func main() {
	if err := cfasuitecli.Execute(os.Args[1:]); err != nil {
		if errors.Is(err, cfasuitecli.ErrUsage) {
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr)
			cfasuitecli.PrintUsage(os.Stderr)
			os.Exit(2)
		}
		log.Fatal(err)
	}
}
