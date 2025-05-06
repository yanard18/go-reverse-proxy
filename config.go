package main

import (
	"flag"
	"fmt"
)

type VerbosityLevel int

const (
	VerbosityNone VerbosityLevel = iota
	VerbosityOriginal
	VerbosityModified
	VerbosityAll
)

var (
	targetDomain   string
	phishingDomain string
	jsPayload      string
	verbosity      VerbosityLevel
)

func init() {
	// Domain flags
	flag.StringVar(&targetDomain, "target", "www.example.com", "Original target domain")
	flag.StringVar(&phishingDomain, "phishing", "localhost", "Phishing domain to inject")

	// Verbosity flags
	flag.Var(&verbosityFlag{}, "verbose", "Log level [original|modified|all]")
	flag.Var(&verbosityFlag{}, "v", "Shorthand for verbose")
}

// Custom flag type for verbosity
type verbosityFlag struct{}

func (v *verbosityFlag) Set(s string) error {
	switch s {
	case "original":
		verbosity = VerbosityOriginal
	case "modified":
		verbosity = VerbosityModified
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
