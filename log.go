package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

var logFilterRes []*regexp.Regexp

func initFilters() {
	for _, pattern := range logFilters {
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Fatalf("Invalid regex pattern %q: %v", pattern, err)
		}
		logFilterRes = append(logFilterRes, re)
	}
}

func ShouldFilter(message string) bool {
	if len(logFilterRes) == 0 { // No filters = show all
		return true
	}

	for _, re := range logFilterRes {
		if re.MatchString(message) {
			return true
		}
	}
	return false
}

func formatHeaders(headers http.Header) string {
	var b strings.Builder
	keys := make([]string, 0, len(headers))

	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, name := range keys {
		b.WriteString(fmt.Sprintf("  %s: ", name))
		values := headers[name]
		for i, value := range values {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(value)
		}
		b.WriteString("\n")
	}
	return b.String()
}
