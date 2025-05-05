package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

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
