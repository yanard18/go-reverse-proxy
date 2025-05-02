package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	target, _ := url.Parse("https://example.com")

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Configure proxy-to-target TLS security
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Disable certificate verification while proxy connect target. It makes my app hackable?
	}

	// Director modify the request before it goes to the target
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host // Critic for SNI in TLS handshake

		// Add security headers
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-For", req.RemoteAddr) // Preserve client IP
	}

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

	server := &http.Server{
		Addr:      ":443",
		Handler:   proxy,
		TLSConfig: tlsConfig,
	}

	log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))

}
