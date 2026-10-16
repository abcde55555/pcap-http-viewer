// Package repeater sends hand-edited HTTP requests (Burp Repeater style) and
// returns the responses. It is stateless; the UI owns request/history state.
package repeater

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options controls how a request is sent.
type Options struct {
	TimeoutMs       int    `json:"timeoutMs"`
	FollowRedirects int    `json:"followRedirects"` // 0 = no redirects, -1 = unlimited
	InsecureTLS     bool   `json:"insecureTLS"`
	UpstreamProxy   string `json:"upstreamProxy"` // http://host:port or empty
	GzipBody        bool   `json:"gzipBody"`       // recompress the request body with gzip
}

func (o Options) timeout() time.Duration {
	if o.TimeoutMs <= 0 {
		return 15 * time.Second
	}
	return time.Duration(o.TimeoutMs) * time.Millisecond
}

// Request is one replay attempt.
type Request struct {
	Scheme  string  `json:"scheme"` // http | https
	Host    string  `json:"host"`   // optional override (host[:port]); empty = use Host header / URI
	RawB64  string  `json:"raw"`    // raw HTTP request (request line + headers + body), base64
	Options Options `json:"options"`
}

// Response is what the UI displays.
type Response struct {
	Proto       string            `json:"proto"`
	StatusCode  int               `json:"statusCode"`
	Reason      string            `json:"reason"`
	Headers     map[string]string `json:"headers"`
	BodyB64     string            `json:"bodyBase64"`
	Length      int               `json:"length"`
	DurationMs  int64             `json:"durationMs"`
	RemoteAddr  string            `json:"remoteAddr"`
	TLSVersion  string            `json:"tlsVersion,omitempty"`
	CipherSuite string            `json:"cipherSuite,omitempty"`
	URL         string            `json:"url"`
	Error       string            `json:"error,omitempty"`
	Redirects   []string          `json:"redirects,omitempty"`
}

// hop-by-hop headers that must not be forwarded (RFC 2616 13.5.1).
var hopHeaders = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"Transfer-Encoding": true, "Upgrade": true, "Proxy-Authorization": true,
	"Proxy-Authenticate": true, "Te": true, "Trailer": true,
}

// Send parses the raw request, sends it, and returns the decoded response.
func Send(req *Request) *Response {
	start := time.Now()
	out := &Response{}

	raw, err := base64.StdEncoding.DecodeString(req.RawB64)
	if err != nil {
		out.Error = "base64 decode: " + err.Error()
		return out
	}

	// Parse the raw HTTP request. We give ReadRequest a server-style reader so
	// request line + headers + body are parsed without requiring a Host URL.
	httpReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		out.Error = "parse request: " + err.Error()
		return out
	}
	defer httpReq.Body.Close()
	body, _ := io.ReadAll(httpReq.Body)

	scheme := strings.ToLower(req.Scheme)
	if scheme == "" {
		scheme = "https"
	}
	host := req.Host
	if host == "" {
		host = httpReq.Host
	}
	if host == "" {
		out.Error = "missing Host"
		return out
	}
	// Strip any default port that would mismatch the scheme.
	host = normalizeHost(scheme, host)
	target := &url.URL{Scheme: scheme, Host: host, Path: httpReq.URL.Path, RawQuery: httpReq.URL.RawQuery}
	out.URL = target.String()

	// Optionally gzip the request body.
	contentEncoding := httpReq.Header.Get("Content-Encoding")
	if req.Options.GzipBody {
		if body, err = gzipBytes(body); err != nil {
			out.Error = "gzip body: " + err.Error()
			return out
		}
		httpReq.Header.Set("Content-Encoding", "gzip")
		contentEncoding = "gzip"
	} else if strings.EqualFold(contentEncoding, "gzip") {
		// Editor content is assumed to be plaintext; if a gzip header leaked in,
		// decompress so we send valid plaintext.
		if decoded, derr := gunzip(body); derr == nil {
			body = decoded
			httpReq.Header.Del("Content-Encoding")
			contentEncoding = ""
		}
	}
	_ = contentEncoding

	// Build the outbound request.
	oreq, err := http.NewRequest(httpReq.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		out.Error = err.Error()
		return out
	}
	// Copy headers except hop-by-hop and ones we manage.
	copyHeaders(oreq.Header, httpReq.Header)
	oreq.Host = host // effective Host header
	oreq.ContentLength = int64(len(body))

	// Transport / client.
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: req.Options.InsecureTLS},
		MaxIdleConns:        1,
		DisableKeepAlives:   true,
		IdleConnTimeout:     10 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if req.Options.UpstreamProxy != "" {
		if pu, err := url.Parse(req.Options.UpstreamProxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	var redirects []string
	client := &http.Client{
		Transport: tr,
		Timeout:   req.Options.timeout(),
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			loc := r.Response.Header.Get("Location")
			redirects = append(redirects, fmt.Sprintf("%d %s", r.Response.StatusCode, loc))
			max := req.Options.FollowRedirects
			if max == 0 {
				return http.ErrUseLastResponse
			}
			if max > 0 && len(via) >= max {
				return http.ErrUseLastResponse
			}
			return nil // -1 = follow all
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), req.Options.timeout()+2*time.Second)
	defer cancel()
	oreq = oreq.WithContext(ctx)

	resp, err := client.Do(oreq)
	out.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		out.Error = err.Error()
		out.Redirects = redirects
		return out
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024)) // cap 50MB

	out.Proto = resp.Proto
	out.StatusCode = resp.StatusCode
	out.Reason = resp.Status
	out.Headers = flattenHeader(resp.Header)
	out.BodyB64 = base64.StdEncoding.EncodeToString(rb)
	out.Length = len(rb)
	out.Redirects = redirects
	if resp.TLS != nil {
		out.TLSVersion = tlsVersionName(resp.TLS.Version)
		out.CipherSuite = tls.CipherSuiteName(resp.TLS.CipherSuite)
	}
	if resp.Request != nil && resp.Request.URL != nil {
		host, port, _ := net.SplitHostPort(resp.Request.URL.Host)
		if host == "" {
			host = resp.Request.URL.Host
		}
		out.RemoteAddr = net.JoinHostPort(host, port)
	}
	return out
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopHeaders[k] {
			continue
		}
		dst[k] = append([]string(nil), vs...)
	}
}

func flattenHeader(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func normalizeHost(scheme, host string) string {
	host = strings.TrimSpace(host)
	if h, p, err := net.SplitHostPort(host); err == nil {
		// Remove redundant default ports.
		if (scheme == "http" && p == "80") || (scheme == "https" && p == "443") {
			return h
		}
		return net.JoinHostPort(h, p)
	}
	// No port; add default.
	if !strings.Contains(host, ":") { // not IPv6 without brackets
		if scheme == "http" {
			return host + ":80"
		}
		return host + ":443"
	}
	return host
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return ""
}

// Seed builds editable raw HTTP request text from a captured transaction. It
// decompresses gzip bodies, removes hop-by-hop / framing headers, and recomputes
// Content-Length so the user can edit plaintext directly.
func Seed(method, rawURL, proto string, headers map[string]string, body []byte, contentEncoding string) (scheme string, host string, raw []byte) {
	scheme = "http"
	host = ""
	if headers != nil {
		host = firstNonEmpty(headers["Host"], headers["host"])
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", orDefault(method, "GET"), orDefault(rawURL, "/"), orDefault(proto, "HTTP/1.1"))
	for k, v := range headers {
		if hopHeaders[k] {
			continue
		}
		if strings.EqualFold(k, "Content-Length") {
			continue // recomputed below
		}
		if strings.EqualFold(k, "Content-Encoding") {
			continue // body is decoded for editing
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	// Decode body if gzip.
	if strings.EqualFold(contentEncoding, "gzip") {
		if decoded, err := gunzip(body); err == nil {
			body = decoded
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	b.WriteString("\r\n")
	b.Write(body)
	return scheme, host, []byte(b.String())
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// MarshalJSON is a small helper so callers can encode responses.
func (r *Response) JSON() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil response")
	}
	return json.Marshal(r)
}
