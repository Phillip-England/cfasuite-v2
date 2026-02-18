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
			fmt.Fprintln(os.Stderr, "usage: cfasuite setup --admin-password <password> [--admin-username admin] [--force]")
			fmt.Fprintln(os.Stderr, "       cfasuite assets build")
			fmt.Fprintln(os.Stderr, "       cfasuite run api|client|all")
			os.Exit(2)
		}
		log.Fatal(err)
	}
}
