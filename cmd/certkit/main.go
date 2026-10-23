package main

import (
	"fmt"
	"os"

	"github.com/relentlessworks/certkit/internal/api"
	"github.com/relentlessworks/certkit/internal/config"
)

func main() {
	cfg := config.FromFlags()
	server := api.New(cfg)
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
