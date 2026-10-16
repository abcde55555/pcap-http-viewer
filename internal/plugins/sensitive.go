package plugins

import (
	"math"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"pcap-http-viewer/internal/model"
)

// Rule is one data-driven sensitive-data matching rule.
type Rule struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Severity    string   `json:"severity" yaml:"severity"`
	Category    string   `json:"category" yaml:"category"`
	Scope       []string `json:"scope" yaml:"scope"` // subset of: url, header, reqbody, respbody, body
	Pattern     string   `json:"pattern" yaml:"pattern"`
	HeaderName  string   `json:"headerName,omitempty" yaml:"headerName,omitempty"` // if set, only match this header (case-insensitive)
	Validator   string   `json:"validator,omitempty" yaml:"validator,omitempty"`   // "id-checksum", "luhn", "jwt"
	Context     int      `json:"context,omitempty" yaml:"context,omitempty"`       // chars of snippet around match
	MaskValue   bool     `json:"maskValue,omitempty" yaml:"maskValue,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	MinEntropy  float64  `json:"minEntropy,omitempty" yaml:"minEntropy,omitempty"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`

	re *regexp.Regexp
}

// IsEnabled returns the rule's enabled state (default true).
func (r *Rule) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// SensitiveEngine is the built-in plugin that scans transactions for sensitive
// data according to a set of compiled Rules.
type SensitiveEngine struct {
	mu    sync.RWMutex
	rules []*Rule
}

// NewSensitiveEngine creates an engine with the given rules. Invalid regexps are
// skipped (returned in the second value).
func NewSensitiveEngine(rules []*Rule) (*SensitiveEngine, []error) {
	e := &SensitiveEngine{}
	var errs []error
	for _, r := range rules {
		if r.Pattern != "" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			r.re = re
		}
		if r.Context == 0 {
			r.Context = 40
		}
		e.rules = append(e.rules, r)
	}
	return e, errs
}

// Name implements Plugin.
func (e *SensitiveEngine) Name() string { return "sensitive" }

// SetRules replaces the rule set at runtime.
func (e *SensitiveEngine) SetRules(rules []*Rule) []error {
	ne, errs := NewSensitiveEngine(rules)
	if len(errs) > 0 {
		return errs
	}
	e.mu.Lock()
	e.rules = ne.rules
	e.mu.Unlock()
	return nil
}

// Rules returns a snapshot of the current rules.
func (e *SensitiveEngine) Rules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// maxBodyScan caps how many decoded body bytes are scanned per message.
const maxBodyScan = 1 << 20 // 1 MiB

// OnTransaction implements Plugin.
func (e *SensitiveEngine) OnTransaction(tx *model.HTTPTx, bodies BodyReader) []model.Finding {
	if tx.IsTLS && tx.Method == "" {
		return nil // encrypted session placeholder — no plaintext to scan
	}
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()
	if len(rules) == 0 {
		return nil
	}

	var findings []model.Finding

	// URL
	if hasScope(rules, "url") && tx.URL != "" {
		findings = append(findings, e.scanText(rules, "url", "", tx.URL)...)
	}

	// Headers
	findings = append(findings, e.scanHeaders(rules, "req.header", tx.RequestHeader)...)
	findings = append(findings, e.scanHeaders(rules, "resp.header", tx.ResponseHeader)...)

	// Bodies
	if hasScope(rules, "reqbody") || hasScope(rules, "body") {
		if b, err := bodies.ReadBody(tx, "req"); err == nil {
			text := bodyToText(b, maxBodyScan)
			findings = append(findings, e.scanText(rules, "req.body", "", text)...)
		}
	}
	if hasScope(rules, "respbody") || hasScope(rules, "body") {
		if b, err := bodies.ReadBody(tx, "resp"); err == nil {
			text := bodyToText(b, maxBodyScan)
			findings = append(findings, e.scanText(rules, "resp.body", "", text)...)
		}
	}
	return findings
}

func (e *SensitiveEngine) scanHeaders(rules []*Rule, loc string, headers map[string]string) []model.Finding {
	if len(headers) == 0 {
		return nil
	}
	var out []model.Finding
	wantHeader := false
	for _, r := range rules {
		if !r.IsEnabled() {
			continue
		}
		if !scopesAny(r, "header") {
			continue
		}
		wantHeader = true
		for name, value := range headers {
			if r.HeaderName != "" && !strings.EqualFold(name, r.HeaderName) {
				continue
			}
			// A rule that targets a header name but has no pattern flags the
			// presence (and optionally masks the value) of that header.
			if r.HeaderName != "" && r.Pattern == "" {
				out = append(out, model.Finding{
					RuleID: r.ID, Name: r.Name, Severity: sev(r.Severity),
					Category: category(r.Category), Location: loc, Header: name,
					Match:   maskIf(r.MaskValue, value),
					Snippet: maskIf(r.MaskValue, value), Length: len(value),
				})
				continue
			}
			if r.re == nil {
				continue
			}
			for _, m := range r.re.FindAllStringIndex(value, -1) {
				match := value[m[0]:m[1]]
				if !e.validates(r, match) {
					continue
				}
				out = append(out, model.Finding{
					RuleID: r.ID, Name: r.Name, Severity: sev(r.Severity),
					Category: category(r.Category), Location: loc, Header: name,
					Offset: m[0], Length: m[1] - m[0],
					Match:   maskIf(r.MaskValue, match),
					Snippet: maskIf(r.MaskValue, snippet(value, m[0], m[1], r.Context)),
				})
			}
		}
	}
	_ = wantHeader
	return out
}

func (e *SensitiveEngine) scanText(rules []*Rule, loc, header, text string) []model.Finding {
	if text == "" {
		return nil
	}
	var out []model.Finding
	for _, r := range rules {
		if !r.IsEnabled() || r.re == nil {
			continue
		}
		if !scopesAny(r, scopeOfLocation(loc)) {
			continue
		}
		for _, m := range r.re.FindAllStringIndex(text, -1) {
			match := text[m[0]:m[1]]
			if !e.validates(r, match) {
				continue
			}
			if r.MinEntropy > 0 && shannonEntropy(match) < r.MinEntropy {
				continue
			}
			out = append(out, model.Finding{
				RuleID: r.ID, Name: r.Name, Severity: sev(r.Severity),
				Category: category(r.Category), Location: loc, Header: header,
				Offset: m[0], Length: m[1] - m[0],
				Match:   maskIf(r.MaskValue, match),
				Snippet: maskIf(r.MaskValue, snippet(text, m[0], m[1], r.Context)),
			})
		}
	}
	return out
}

func (e *SensitiveEngine) validates(r *Rule, value string) bool {
	switch r.Validator {
	case "id-checksum":
		return validChineseID(value)
	case "luhn":
		return validLuhn(value)
	case "jwt":
		return strings.Count(value, ".") == 2
	default:
		return true
	}
}

// scopeOfLocation maps a finding location to a rule scope token.
func scopeOfLocation(loc string) string {
	switch loc {
	case "url":
		return "url"
	case "req.header", "resp.header":
		return "header"
	case "req.body":
		return "reqbody"
	case "resp.body":
		return "respbody"
	}
	return ""
}

func hasScope(rules []*Rule, scope string) bool {
	for _, r := range rules {
		if r.IsEnabled() && scopesAny(r, scope) {
			return true
		}
	}
	return false
}

func scopesAny(r *Rule, scope string) bool {
	for _, s := range r.Scope {
		if s == scope {
			return true
		}
	}
	return false
}

func sev(s string) string {
	switch s {
	case model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical:
		return s
	default:
		return model.SeverityInfo
	}
}

func category(c string) string {
	if c == "" {
		return "general"
	}
	return c
}

func snippet(text string, start, end, ctx int) string {
	if ctx <= 0 {
		ctx = 40
	}
	lo := start - ctx
	if lo < 0 {
		lo = 0
	}
	hi := end + ctx
	if hi > len(text) {
		hi = len(text)
	}
	return strings.ToValidUTF8(text[lo:hi], "")
}

func maskIf(mask bool, s string) string {
	if !mask || len(s) <= 8 {
		return s
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

// bodyToText returns up to max bytes of valid UTF-8 text, or empty for binary.
func bodyToText(b []byte, max int) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > max {
		b = b[:max]
	}
	// Heuristic: if it contains a NUL byte, treat as binary.
	if strings.IndexByte(string(b), 0) >= 0 {
		return ""
	}
	if !utf8.Valid(b) {
		return ""
	}
	return string(b)
}

// ---------- validators ----------

// validChineseID validates an 18-digit Chinese resident ID with its checksum.
func validChineseID(s string) bool {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 18 {
		return false
	}
	for i := 0; i < 17; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checks := []byte{'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'}
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(s[i]-'0') * weights[i]
	}
	return checks[sum%11] == s[17]
}

// validLuhn validates a card number using the Luhn algorithm.
func validLuhn(s string) bool {
	digits := make([]int, 0, len(s))
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 12 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := digits[i]
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// shannonEntropy computes the Shannon entropy (bits/byte) of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]float64{}
	n := 0.0
	for _, r := range s {
		freq[r]++
		n++
	}
	var h float64
	for _, c := range freq {
		p := c / n
		if p > 0 {
			h -= p * math.Log2(p)
		}
	}
	return h
}
