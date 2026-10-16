// Package storage holds parsed HTTP transactions and their bodies. Small bodies
// are kept inline; larger bodies are spilled into a single append-only file so
// that opening a big capture does not pin every body in memory.
package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"pcap-http-viewer/internal/model"
)

// InlineLimit is the maximum body size kept in memory (per message).
var InlineLimit int64 = 256 * 1024

// Store is a concurrency-safe collection of parsed transactions.
type Store struct {
	mu       sync.RWMutex
	txs      []*model.HTTPTx
	byID     map[int64]*model.HTTPTx
	spill    *os.File
	spillPath string
	spillOff int64
	spillMu  sync.Mutex

	// Stream summaries derived from transactions.
	streamsOnce sync.Once
	streams     []*model.StreamSummary

	fileName string
}

// New creates an empty store. Large bodies are spilled into a temp file.
func New() (*Store, error) {
	dir, err := os.MkdirTemp("", "pcapview-*")
	if err != nil {
		return nil, err
	}
	spillPath := filepath.Join(dir, "bodies.bin")
	f, err := os.Create(spillPath)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return &Store{
		byID:      make(map[int64]*model.HTTPTx),
		spill:     f,
		spillPath: spillPath,
	}, nil
}

// SetFileName records the capture file name for display.
func (s *Store) SetFileName(name string) {
	s.mu.Lock()
	s.fileName = name
	s.mu.Unlock()
}

// FileName returns the recorded capture file name.
func (s *Store) FileName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fileName
}

// AddTransaction implements parser.Sink. It spills large bodies to disk.
func (s *Store) AddTransaction(tx *model.HTTPTx) {
	s.spillBody(&tx.RequestBody)
	s.spillBody(&tx.ResponseBody)

	s.mu.Lock()
	tx.ID = int64(len(s.txs)) + 1
	s.txs = append(s.txs, tx)
	s.byID[tx.ID] = tx
	s.mu.Unlock()
}

// SetStreamCount satisfies parser.Sink; stream summaries are derived lazily.
func (s *Store) SetStreamCount(int) {}

func (s *Store) spillBody(b *model.BodyRef) {
	if !b.Inline || len(b.Data) == 0 {
		return
	}
	if int64(len(b.Data)) <= InlineLimit {
		return
	}
	s.spillMu.Lock()
	off := s.spillOff
	n, err := s.spill.WriteAt(b.Data, off)
	if err == nil {
		s.spillOff += int64(n)
	}
	s.spillMu.Unlock()
	if err != nil {
		return // keep inline on write failure
	}
	b.File = s.spillPath
	b.Offset = off
	b.Inline = false
	b.Data = nil
}

// Count returns the number of stored transactions.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.txs)
}

// Get returns a transaction by ID.
func (s *Store) Get(id int64) (*model.HTTPTx, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, ok := s.byID[id]
	return tx, ok
}

// ForEach iterates over all transactions in order. The callback must not retain tx.
func (s *Store) ForEach(fn func(tx *model.HTTPTx)) {
	s.mu.RLock()
	txs := s.txs
	s.mu.RUnlock()
	for _, tx := range txs {
		fn(tx)
	}
}

// Metadata is the lightweight per-transaction record sent to the list view
// (no headers, no bodies).
type Metadata struct {
	ID         int64     `json:"id"`
	StartTime  int64     `json:"t"`            // unix millis
	Method     string    `json:"m,omitempty"`
	Host       string    `json:"h,omitempty"`
	URL        string    `json:"u,omitempty"`
	StatusCode int       `json:"s,omitempty"`
	ReqSize    int64     `json:"rs"`
	RespSize   int64     `json:"ps"`
	DurationMs int64     `json:"d"`
	ContentType string   `json:"ct,omitempty"`
	IsTLS      bool      `json:"tls"`
	SNI        string    `json:"sni,omitempty"`
	SrcIP      string    `json:"ip,omitempty"`
	SrcPort    int       `json:"sp,omitempty"`
	DstIP      string    `json:"dip,omitempty"`
	DstPort    int       `json:"dp,omitempty"`
	SevMax     string    `json:"sev,omitempty"` // highest finding severity
	Findings   int       `json:"fn"`
}

// Metadata returns light metadata for all transactions, in order.
func (s *Store) Metadata() []Metadata {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Metadata, 0, len(s.txs))
	for _, tx := range s.txs {
		m := Metadata{
			ID:         tx.ID,
			Method:     tx.Method,
			Host:       tx.Host,
			URL:        tx.URL,
			StatusCode: tx.StatusCode,
			ReqSize:    tx.RequestSize,
			RespSize:   tx.ResponseSize,
			DurationMs: tx.DurationMs,
			ContentType: tx.ContentType,
			IsTLS:      tx.IsTLS,
			SNI:        tx.SNI,
			SrcIP:      tx.SrcIP,
			SrcPort:    tx.SrcPort,
			DstIP:      tx.DstIP,
			DstPort:    tx.DstPort,
			Findings:   len(tx.Findings),
			SevMax:     maxSeverity(tx.Findings),
		}
		if !tx.StartTime.IsZero() {
			m.StartTime = tx.StartTime.UnixMilli()
		}
		out = append(out, m)
	}
	return out
}

// Detail is a transaction with full headers but no body bytes.
type Detail struct {
	model.HTTPTx
	ReqBodyPresent  bool `json:"reqBodyPresent"`
	RespBodyPresent bool `json:"respBodyPresent"`
}

// Detail returns a transaction detail with headers but bodies omitted.
func (s *Store) Detail(id int64) (*Detail, error) {
	s.mu.RLock()
	tx, ok := s.byID[id]
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	// Copy and clear body bytes.
	cp := *tx
	cp.RequestBody = model.BodyRef{
		Inline:        false,
		File:          "",
		Length:        tx.RequestBody.Length,
		Encoding:      tx.RequestBody.Encoding,
		DecodedLength: tx.RequestBody.DecodedLength,
	}
	cp.ResponseBody = model.BodyRef{
		Inline:        false,
		Length:        tx.ResponseBody.Length,
		Encoding:      tx.ResponseBody.Encoding,
		DecodedLength: tx.ResponseBody.DecodedLength,
	}
	return &Detail{
		HTTPTx:          cp,
		ReqBodyPresent:  tx.RequestBody.Length > 0,
		RespBodyPresent: tx.ResponseBody.Length > 0,
	}, nil
}

// ReadBody returns up to limit bytes of a message body starting at offset.
// A limit <= 0 means "read to EOF".
func (s *Store) ReadBody(id int64, side string, offset, limit int64) ([]byte, error) {
	s.mu.RLock()
	tx, ok := s.byID[id]
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	var ref *model.BodyRef
	switch side {
	case "req":
		ref = &tx.RequestBody
	case "resp":
		ref = &tx.ResponseBody
	default:
		return nil, fmt.Errorf("unknown side %q", side)
	}
	if offset < 0 || offset >= ref.Length {
		return nil, io.EOF
	}
	if limit <= 0 || offset+limit > ref.Length {
		limit = ref.Length - offset
	}
	buf := make([]byte, limit)
	if ref.Inline {
		n := copy(buf, ref.Data[offset:])
		return buf[:n], nil
	}
	if ref.File == "" {
		return nil, errors.New("body not available")
	}
	f, err := os.Open(ref.File)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	n, err := f.ReadAt(buf, ref.Offset+offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

// StreamSummaries returns per-TCP-stream summaries derived from transactions.
func (s *Store) StreamSummaries() []*model.StreamSummary {
	s.streamsOnce.Do(func() {
		s.mu.RLock()
		defer s.mu.RUnlock()
		groups := make(map[int64]*model.StreamSummary)
		for _, tx := range s.txs {
			g, ok := groups[tx.StreamID]
			if !ok {
				g = &model.StreamSummary{
					ID:         tx.StreamID,
					SrcIP:      tx.SrcIP,
					SrcPort:    tx.SrcPort,
					DstIP:      tx.DstIP,
					DstPort:    tx.DstPort,
					IsTLS:      tx.IsTLS,
					SNI:        tx.SNI,
					TLSVersion: tx.TLSVersion,
					FirstSeen:  tx.StartTime,
				}
				groups[tx.StreamID] = g
			}
			g.BytesC2S += tx.RequestSize
			g.BytesS2C += tx.ResponseSize
			g.TxCount++
			if tx.EndTime.After(g.LastSeen) {
				g.LastSeen = tx.EndTime
			}
		}
		out := make([]*model.StreamSummary, 0, len(groups))
		for _, g := range groups {
			out = append(out, g)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		s.streams = out
	})
	return s.streams
}

// GlobalFinding is one finding enriched with the transaction context it was
// found in, for the global sensitive-info view.
type GlobalFinding struct {
	model.Finding
	TxID   int64  `json:"txId"`
	Method string `json:"method,omitempty"`
	Host   string `json:"host,omitempty"`
	URL    string `json:"url,omitempty"`
	Status int    `json:"status,omitempty"`
	Time   int64  `json:"t"`
	SrcIP  string `json:"srcIp,omitempty"`
	DstIP  string `json:"dstIp,omitempty"`
	IsTLS  bool   `json:"tls"`
}

// RuleGroup groups all findings under one rule.
type RuleGroup struct {
	RuleID   string          `json:"ruleId"`
	Name     string          `json:"name"`
	Severity string          `json:"severity"`
	Category string          `json:"category"`
	Count    int             `json:"count"`
	Items    []GlobalFinding `json:"items"`
}

// AllFindings returns every finding grouped by rule, across all transactions.
// If a non-empty ruleID filter is given, only that rule's findings are returned.
func (s *Store) AllFindings(ruleID string) []RuleGroup {
	groups := map[string]*RuleGroup{}
	var order []string
	s.mu.RLock()
	for _, tx := range s.txs {
		for _, f := range tx.Findings {
			if ruleID != "" && f.RuleID != ruleID {
				continue
			}
			g, ok := groups[f.RuleID]
			if !ok {
				g = &RuleGroup{RuleID: f.RuleID, Name: f.Name, Severity: f.Severity, Category: f.Category}
				groups[f.RuleID] = g
				order = append(order, f.RuleID)
			}
			g.Count++
			g.Items = append(g.Items, GlobalFinding{
				Finding: f, TxID: tx.ID, Method: tx.Method, Host: tx.Host,
				URL: tx.URL, Status: tx.StatusCode,
				Time: tx.StartTime.UnixMilli(), SrcIP: tx.SrcIP, DstIP: tx.DstIP, IsTLS: tx.IsTLS,
			})
		}
	}
	s.mu.RUnlock()
	out := make([]RuleGroup, 0, len(order))
	for _, id := range order {
		out = append(out, *groups[id])
	}
	return out
}

// ReplaceFindings replaces ALL findings (transactions absent from m have their
// findings cleared), so disabling/removing rules actually removes stale hits.
func (s *Store) ReplaceFindings(m map[int64][]model.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tx := range s.txs {
		if f, ok := m[tx.ID]; ok {
			tx.Findings = f
		} else {
			tx.Findings = nil
		}
	}
	s.streamsOnce = sync.Once{} // invalidate derived streams cache
}

// Close removes spill storage.
func (s *Store) Close() error {
	s.spillMu.Lock()
	defer s.spillMu.Unlock()
	if s.spill != nil {
		name := s.spill.Name()
		_ = s.spill.Close()
		_ = os.Remove(name)
		_ = os.RemoveAll(filepath.Dir(name))
	}
	return nil
}

// MarshalJSON for Store emits metadata (used for debugging).
func (s *Store) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Metadata())
}

var severityRank = map[string]int{
	model.SeverityInfo: 1, model.SeverityLow: 2, model.SeverityMedium: 3,
	model.SeverityHigh: 4, model.SeverityCritical: 5,
}

func maxSeverity(fs []model.Finding) string {
	best := ""
	rank := 0
	for _, f := range fs {
		if r, ok := severityRank[f.Severity]; ok && r > rank {
			rank = r
			best = f.Severity
		}
	}
	return best
}
