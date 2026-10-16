// Package model defines the shared data structures for captured streams and HTTP transactions.
package model

import "time"

// BodyRef is a reference to a message body. Small bodies are stored inline in Data;
// large bodies are spilled to File (with Offset/Length) to avoid keeping them in memory.
type BodyRef struct {
	Inline bool   `json:"inline"`          // true if Data holds the full body
	Data   []byte `json:"-"`               // inline body bytes (not serialized directly)
	File   string `json:"file,omitempty"`  // absolute path to spill file
	Offset int64  `json:"offset,omitempty"`// offset within File
	Length int64  `json:"length"`          // body length in bytes
	// Encoding is the original Content-Encoding applied (gzip/deflate/br/identity).
	Encoding string `json:"encoding,omitempty"`
	// DecodedLength is the length after content-encoding decoding (0 if not encoded).
	DecodedLength int64 `json:"decodedLength,omitempty"`
}

// HTTPTx is one request/response pair (or a request without response, or response without request).
type HTTPTx struct {
	ID int64 `json:"id"`
	// StreamID identifies the TCP stream this transaction belongs to.
	StreamID int64 `json:"streamId"`
	// IndexWithinStream is the 0-based sequence number of the request on that stream.
	IndexWithinStream int `json:"indexWithinStream"`

	StartTime time.Time `json:"startTime"` // request start time
	EndTime   time.Time `json:"endTime"`   // response end time (zero if no response)
	DurationMs int64   `json:"durationMs"`

	// Request
	Method        string            `json:"method,omitempty"`
	Host          string            `json:"host,omitempty"`
	URL           string            `json:"url,omitempty"` // path + query
	FullURL       string            `json:"fullUrl,omitempty"`
	HTTPVersion   string            `json:"httpVersion,omitempty"`
	RequestHeader map[string]string `json:"requestHeader,omitempty"`
	RequestBody   BodyRef           `json:"requestBody"`
	RequestSize   int64             `json:"requestSize"`

	// Response
	StatusCode     int               `json:"statusCode,omitempty"`
	ReasonPhrase   string            `json:"reasonPhrase,omitempty"`
	ResponseHeader map[string]string `json:"responseHeader,omitempty"`
	ResponseBody   BodyRef           `json:"responseBody"`
	ResponseSize   int64             `json:"responseSize"`
	ContentType    string            `json:"contentType,omitempty"`

	// Source/destination at the time of the request.
	SrcIP   string `json:"srcIp,omitempty"`
	SrcPort int    `json:"srcPort,omitempty"`
	DstIP   string `json:"dstIp,omitempty"`
	DstPort int    `json:"dstPort,omitempty"`

	// TLS metadata (set when the transport was TLS, even though we cannot decrypt it).
	IsTLS      bool   `json:"isTLS"`
	SNI        string `json:"sni,omitempty"`
	TLSVersion string `json:"tlsVersion,omitempty"`
	Cipher     string `json:"cipher,omitempty"`

	// Findings from plugins (e.g. sensitive-info matches), keyed by rule id.
	Findings []Finding `json:"findings,omitempty"`
}

// Severity levels.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Finding is a single plugin match on a transaction (e.g. a sensitive value).
type Finding struct {
	RuleID   string `json:"ruleId"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	// Where the match was: "req.header", "resp.header", "req.body", "resp.body", "url".
	Location string `json:"location"`
	// For header matches, the header name; for body matches, byte offset.
	Header string `json:"header,omitempty"`
	Offset int    `json:"offset,omitempty"`
	Length int    `json:"length"`
	// Match is the exact matched value (may be masked when MaskValue is set).
	Match string `json:"match,omitempty"`
	// Snippet is a short human-readable context around the match (may be masked).
	Snippet string `json:"snippet,omitempty"`
}

// StreamSummary is a lightweight TCP-stream-level record (used for TLS-only streams
// that have no decrypted HTTP transaction).
type StreamSummary struct {
	ID         int64     `json:"id"`
	SrcIP      string    `json:"srcIp"`
	SrcPort    int       `json:"srcPort"`
	DstIP      string    `json:"dstIp"`
	DstPort    int       `json:"dstPort"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	BytesC2S   int64     `json:"bytesC2s"`
	BytesS2C   int64     `json:"bytesS2c"`
	IsTLS      bool      `json:"isTls"`
	SNI        string    `json:"sni,omitempty"`
	TLSVersion string    `json:"tlsVersion,omitempty"`
	Cipher     string    `json:"cipher,omitempty"`
	TxCount    int       `json:"txCount"`
}
