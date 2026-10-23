package config

import (
	"flag"
	"fmt"
	"os"
)

// Config holds the application configuration.
type Config struct {
	Port     int
	Host     string
	DataDir  string
	Version  string
}

// Default returns a Config with default values.
func Default() Config {
	return Config{
		Port:    8470,
		Host:    "0.0.0.0",
		DataDir: "./data",
		Version: "0.1.0",
	}
}

// FromFlags parses command-line flags and returns a Config.
// Config layering: defaults < env < flags
func FromFlags() Config {
	c := Default()

	// Environment variables
	if v := os.Getenv("CERTKIT_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &c.Port)
	}
	if v := os.Getenv("CERTKIT_HOST"); v != "" {
		c.Host = v
	}
	if v := os.Getenv("CERTKIT_DATA_DIR"); v != "" {
		c.DataDir = v
	}

	// Flags (override env)
	flag.IntVar(&c.Port, "port", c.Port, "HTTP server port")
	flag.StringVar(&c.Host, "host", c.Host, "HTTP server host")
	flag.StringVar(&c.DataDir, "data-dir", c.DataDir, "Data directory")
	flag.Parse()

	return c
}

// Addr returns the listen address (host:port).
func (c Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
