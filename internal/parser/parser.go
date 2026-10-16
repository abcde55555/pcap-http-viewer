// Package parser reads pcap/pcapng files, reassembles TCP streams, parses
// HTTP/1.1 requests and responses, pairs them into transactions, and extracts
// TLS metadata (SNI, version) for encrypted streams. It is streaming and
// concurrency-safe; bodies are handed to a storage.Sink to decide inline vs spill.
package parser

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/gopacket/gopacket/tcpassembly"

	"pcap-http-viewer/internal/model"
)

// Config controls parser behavior.
type Config struct {
	// MaxBodyBytes caps the number of body bytes stored per message (0 = 25MB default).
	MaxBodyBytes int64
	// FlushInterval forces idle streams to flush after this much capture time.
	FlushInterval time.Duration
}

func (c *Config) defaults() {
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 25 * 1024 * 1024
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 60 * time.Second
	}
}

// Sink receives parsed transactions and stream metadata.
type Sink interface {
	AddTransaction(tx *model.HTTPTx)
	SetStreamCount(n int)
}

// Stats holds parse progress counters.
type Stats struct {
	Packets     int64
	Transactions int64
	TLSSessions int64
	Errors      int64
	TotalFrames int64 // -1 if unknown
}

// Parser is a single-use pcap reader.
type Parser struct {
	cfg   Config
	path  string
	sink  Sink
	stats Stats
}

// New creates a parser for the given pcap/pcapng file.
func New(path string, sink Sink, cfg Config) *Parser {
	cfg.defaults()
	return &Parser{path: path, sink: sink, cfg: cfg}
}

// Run performs the parse. It returns once the file is fully consumed.
func (p *Parser) Run(ctx context.Context) error {
	f, err := openReader(p.path)
	if err != nil {
		return err
	}
	defer f.close()

	ng, err := pcapgo.NewNgReader(f.file, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		// Not a pcapng — try classic pcap.
		if _, serr := f.file.Seek(0, io.SeekStart); serr != nil {
			return fmt.Errorf("pcapng: %w (seek: %v)", err, serr)
		}
		return p.runClassic(ctx, f)
	}
	return p.runAssembler(ctx, ng, ng.LinkType())
}

func (p *Parser) runClassic(ctx context.Context, f *multiReader) error {
	r, err := pcapgo.NewReader(f.file)
	if err != nil {
		return fmt.Errorf("not a valid pcap/pcapng: %w", err)
	}
	return p.runAssembler(ctx, r, r.LinkType())
}

func (p *Parser) runAssembler(ctx context.Context, sr packetSource, linkType layers.LinkType) error {
	mgr := newConnManager(p.sink, p.cfg, &p.stats)
	pool := tcpassembly.NewStreamPool(mgr)
	asm := tcpassembly.NewAssembler(pool)
	// Bound memory used for out-of-order pages.
	asm.AssemblerOptions.MaxBufferedPagesTotal = 200000
	asm.AssemblerOptions.MaxBufferedPagesPerConnection = 20000

	// Lazy + NoCopy: decode only what we ask for, no extra allocation.
	opts := gopacket.DecodeOptions{Lazy: true, NoCopy: true}

	var lastFlush time.Time
	count := int64(0)

	for {
		select {
		case <-ctx.Done():
			asm.FlushAll()
			mgr.closeAll()
			return ctx.Err()
		default:
		}
		data, ci, err := sr.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			atomic.AddInt64(&p.stats.Errors, 1)
			continue
		}
		count++
		atomic.StoreInt64(&p.stats.Packets, count)

		// Decode Ethernet/IP/TCP through gopacket so that layer flows (and
		// therefore TCP stream keys) are correct. NoCopy avoids a data copy.
		pkt := gopacket.NewPacket(data, linkType, opts)
		if pkt == nil {
			continue
		}
		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		nl := pkt.NetworkLayer()
		if nl == nil {
			continue
		}
		netFlow := nl.NetworkFlow()
		transFlow := tcp.TransportFlow()
		payload := tcp.Payload

		// Record the SYN initiator as the client, and detect TLS ClientHello SNI
		// directly from the first client payload (robust against TLS decode quirks).
		srcIP, srcPort := flowSrc(netFlow, transFlow)
		if tcp.SYN && !tcp.ACK {
			mgr.setClient(netFlow, transFlow, srcIP, srcPort)
		}
		if len(payload) > 0 {
			mgr.maybeRecordSNI(netFlow, transFlow, srcIP, srcPort, payload, ci.Timestamp)
		}

		asm.AssembleWithTimestamp(netFlow, tcp, ci.Timestamp)

		if ci.Timestamp.Sub(lastFlush) > p.cfg.FlushInterval {
			asm.FlushOlderThan(ci.Timestamp.Add(-p.cfg.FlushInterval))
			lastFlush = ci.Timestamp
		}
	}

	asm.FlushAll()
	mgr.closeAll()
	atomic.StoreInt64(&p.stats.TotalFrames, count)
	p.sink.SetStreamCount(mgr.streamCount())
	return nil
}

// Stats returns a snapshot of parse statistics.
func (p *Parser) Stats() Stats {
	return Stats{
		Packets:      atomic.LoadInt64(&p.stats.Packets),
		Transactions: atomic.LoadInt64(&p.stats.Transactions),
		TLSSessions:  atomic.LoadInt64(&p.stats.TLSSessions),
		Errors:       atomic.LoadInt64(&p.stats.Errors),
		TotalFrames:  atomic.LoadInt64(&p.stats.TotalFrames),
	}
}

// ---------- connection manager ----------

type connKey string

type connManager struct {
	cfg      Config
	sink     Sink
	stats    *Stats
	mu       sync.Mutex
	conns    map[connKey]*connection
	txSeq    int64
}

func newConnManager(sink Sink, cfg Config, stats *Stats) *connManager {
	return &connManager{sink: sink, cfg: cfg, stats: stats, conns: make(map[connKey]*connection)}
}

func canonicalKey(netFlow, transFlow gopacket.Flow) (connKey, string) {
	a := fmt.Sprintf("%s:%d->%s:%d",
		netFlow.Src().String(),
		endianPort(transFlow.Src().Raw()),
		netFlow.Dst().String(),
		endianPort(transFlow.Dst().Raw()))
	b := fmt.Sprintf("%s:%d->%s:%d",
		netFlow.Dst().String(),
		endianPort(transFlow.Dst().Raw()),
		netFlow.Src().String(),
		endianPort(transFlow.Src().Raw()))
	if a < b {
		return connKey(a + "|" + b), a
	}
	return connKey(b + "|" + a), a
}

func endianPort(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}

// New implements tcpassembly.StreamFactory.
func (m *connManager) New(netFlow, transFlow gopacket.Flow) tcpassembly.Stream {
	key, direction := canonicalKey(netFlow, transFlow)
	m.mu.Lock()
	c, ok := m.conns[key]
	if !ok {
		c = newConnection(string(key), m)
		m.conns[key] = c
	}
	m.mu.Unlock()

	s := newStream(netFlow, transFlow, false)
	h := &halfStream{stream: s, direction: direction, conn: c}
	c.registerHalf(h)
	return s
}

func (m *connManager) setClient(netFlow, transFlow gopacket.Flow, ip []byte, port int) {
	key, _ := canonicalKey(netFlow, transFlow)
	client := fmt.Sprintf("%s:%d", netIPString(ip), port)
	m.mu.Lock()
	if c, ok := m.conns[key]; ok {
		c.setClient(client)
	}
	m.mu.Unlock()
}

func (m *connManager) maybeRecordSNI(netFlow, transFlow gopacket.Flow, ip []byte, port int, payload []byte, ts time.Time) {
	if len(payload) < 6 || payload[0] != 0x16 {
		return // not a TLS handshake record
	}
	sni, ver := parseSNI(payload)
	if sni == "" && ver == "" {
		return
	}
	key, _ := canonicalKey(netFlow, transFlow)
	client := fmt.Sprintf("%s:%d", netIPString(ip), port)
	m.mu.Lock()
	c, ok := m.conns[key]
	if !ok {
		c = newConnection(string(key), m)
		m.conns[key] = c
	}
	m.mu.Unlock()
	c.recordTLS(client, sni, ver, ts)
}

func (m *connManager) nextTxID() int64 {
	return atomic.AddInt64(&m.txSeq, 1)
}

func (m *connManager) streamCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.conns)
}

func (m *connManager) closeAll() {
	m.mu.Lock()
	cs := make([]*connection, 0, len(m.conns))
	for _, c := range m.conns {
		cs = append(cs, c)
	}
	m.mu.Unlock()
	for _, c := range cs {
		c.shutdown()
	}
}

// ---------- one TCP connection (both directions) ----------

type halfStream struct {
	*stream
	direction string // "ip:port->ip:port" exactly as packets flow
	conn      *connection
}

type requestEvent struct {
	method      string
	host        string
	url         string
	fullURL     string
	version     string
	header      map[string]string
	body        []byte
	bodyEnc     string
	req         *http.Request
	start, end  time.Time
	srcIP       string
	srcPort     int
	dstIP       string
	dstPort     int
	requestSize int64
}

type responseEvent struct {
	statusCode   int
	reason       string
	header       map[string]string
	body         []byte
	bodyEnc      string
	resp         *http.Response
	start, end   time.Time
	responseSize int64
}

type connection struct {
	key    string
	mgr    *connManager
	mu     sync.Mutex
	halves map[string]*halfStream

	client     string
	clientSet  bool
	reqHalf    *halfStream
	respHalf   *halfStream
	classified bool

	isTLS      bool
	sni        string
	tlsVersion string
	tlsCipher  string
	tlsFirst   time.Time

	// endpoints populated from the first half we see (for TLS-only records).
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int

	// pairing
	pendingReqs chan *requestEvent
	reqDone     chan struct{}
	reqDoneOnce sync.Once
	closeOnce   sync.Once
	wg          sync.WaitGroup

	txEmitted int
}

func newConnection(key string, mgr *connManager) *connection {
	return &connection{
		key:         key,
		mgr:         mgr,
		halves:      make(map[string]*halfStream),
		pendingReqs: make(chan *requestEvent, 4096),
		reqDone:     make(chan struct{}),
	}
}

func (c *connection) registerHalf(h *halfStream) {
	c.mu.Lock()
	c.halves[h.direction] = h
	if c.srcIP == "" {
		c.srcIP = h.netFlow.Src().String()
		c.srcPort = endianPort(h.transFlow.Src().Raw())
		c.dstIP = h.netFlow.Dst().String()
		c.dstPort = endianPort(h.transFlow.Dst().Raw())
	}
	c.wg.Add(1)
	c.mu.Unlock()
	go c.runHalf(h)
}

func (c *connection) setClient(client string) {
	c.mu.Lock()
	if c.clientSet {
		c.mu.Unlock()
		return
	}
	c.client = client
	c.clientSet = true
	c.tryClassifyLocked(nil)
	c.mu.Unlock()
}

func (c *connection) recordTLS(client, sni, ver string, ts time.Time) {
	c.mu.Lock()
	c.isTLS = true
	if c.sni == "" {
		c.sni = sni
	}
	if ver != "" {
		c.tlsVersion = ver
	}
	if c.tlsFirst.IsZero() {
		c.tlsFirst = ts
	}
	if !c.clientSet {
		c.client = client
		c.clientSet = true
	}
	c.mu.Unlock()
}

// tryClassifyLocked assigns request/response halves once the client is known
// (or by port heuristic). Requires the half to be registered. h may be nil when
// the client was learned via setClient before both halves arrived.
func (c *connection) tryClassifyLocked(h *halfStream) {
	if c.classified {
		return
	}
	// Determine client endpoint if not known via SYN: use lower ephemeral-port
	// heuristic reversed — the server listens on the lower/well-known port.
	if !c.clientSet {
		// Wait until both halves present, then guess by port.
		if len(c.halves) < 2 {
			return
		}
		var d0, d1 string
		for d := range c.halves {
			if d0 == "" {
				d0 = d
			} else {
				d1 = d
			}
		}
		p0 := portOfDirection(d0)
		p1 := portOfDirection(d1)
		// Client is the side with the higher port (ephemeral), server the lower.
		if p0 != p1 {
			if p0 > p1 {
				c.client = srcEndpointOf(d0)
			} else {
				c.client = srcEndpointOf(d1)
			}
			c.clientSet = true
		}
	}
	if !c.clientSet {
		return
	}
	// Now map halves.
	for d, hh := range c.halves {
		if srcEndpointOf(d) == c.client {
			hh.isClient = true
			c.reqHalf = hh
		} else {
			c.respHalf = hh
		}
	}
	if c.reqHalf != nil && c.respHalf != nil {
		c.classified = true
	}
}

const maxPeek = 8

func (c *connection) runHalf(h *halfStream) {
	defer c.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("stream %s panic: %v", c.key, r)
		}
	}()

	tr := &timedReader{s: h.stream}
	buf := bufio.NewReaderSize(tr, 128*1024)

	// Direction is determined by content (robust against missing SYNs and
	// mid-stream joins): requests start with a method, responses with "HTTP/",
	// and TLS with a record-type byte 0x14-0x17 followed by 0x03.
	peek, perr := buf.Peek(maxPeek)
	if len(peek) == 0 && perr != nil {
		return
	}
	switch {
	case looksLikeTLS(peek):
		c.recordTLSFromHalf(h, peek)
		io.Copy(io.Discard, buf)
		return
	case looksLikeRequest(peek):
		h.isClient = true
		c.runRequests(h, buf, tr)
	case looksLikeResponse(peek):
		h.isClient = false
		c.runResponses(h, buf, tr)
	default:
		// Non-HTTP, non-TLS traffic on this half — drain so assembly never blocks.
		io.Copy(io.Discard, buf)
		return
	}
}

func (c *connection) runRequests(h *halfStream, buf *bufio.Reader, tr *timedReader) {
	defer c.reqDoneOnce.Do(func() { close(c.reqDone) })
	for {
		// Peek to confirm direction (may be TLS or non-HTTP).
		peek, _ := buf.Peek(maxPeek)
		if len(peek) == 0 {
			return
		}
		if looksLikeTLS(peek) {
			c.recordTLSFromHalf(h, peek)
			io.Copy(io.Discard, buf)
			return
		}
		if !looksLikeRequest(peek) {
			// Not HTTP on this half; discard.
			io.Copy(io.Discard, buf)
			return
		}

		tr.reset()
		req, err := http.ReadRequest(buf)
		if err != nil {
			return
		}
		start := tr.msgStart
		body, enc, err := readBodyCappedEncoding(req.Body, c.mgr.cfg.MaxBodyBytes, req.Header.Get("Content-Encoding"))
		end := h.lastSeen
		if start.IsZero() {
			start = end
		}
		_ = req.Body.Close()

		ev := &requestEvent{
			method:      req.Method,
			host:        req.Host,
			url:         req.URL.RequestURI(),
			version:     req.Proto,
			header:      flattenHeader(req.Header),
			body:        body,
			bodyEnc:     enc,
			req:         req,
			start:       start,
			end:         end,
			srcIP:       h.netFlow.Src().String(),
			srcPort:     endianPort(h.transFlow.Src().Raw()),
			dstIP:       h.netFlow.Dst().String(),
			dstPort:     endianPort(h.transFlow.Dst().Raw()),
			requestSize: int64(len(body)) + headerSize(req.Header),
		}
		if req.URL != nil {
			ev.fullURL = requestURL(req)
		}

		if err != nil && !errors.Is(err, errBodyTruncated) {
			// Malformed body framing — still emit what we have, then stop.
			select {
			case c.pendingReqs <- ev:
			default:
			}
			return
		}
		select {
		case c.pendingReqs <- ev:
		default:
			// Channel full (shouldn't happen with large buffer) — drop to avoid deadlock.
			return
		}
	}
}

func (c *connection) runResponses(h *halfStream, buf *bufio.Reader, tr *timedReader) {
	for {
		// Parse the response from the stream FIRST — this keeps draining bytes
		// so assembly can never deadlock. In HTTP/1.x the request always precedes
		// its response, so by the time a full response is parsed the matching
		// request is already buffered in pendingReqs.
		peek, _ := buf.Peek(maxPeek)
		if len(peek) == 0 {
			// Stream ended. Emit any requests that never got a response.
			c.drainPending()
			return
		}
		if looksLikeTLS(peek) {
			c.recordTLSFromHalf(h, peek)
			io.Copy(io.Discard, buf)
			return
		}
		if !looksLikeResponse(peek) {
			io.Copy(io.Discard, buf)
			return
		}

		// Consume the matching request once: it supplies both the *http.Request
		// for body framing and the pairing metadata. If it has not been pushed
		// yet (shouldn't happen in HTTP/1.x), parse without it and pair as nil.
		req := c.takeRequest()
		var stdReq *http.Request
		if req != nil {
			stdReq = req.req
		}

		tr.reset()
		resp, err := http.ReadResponse(buf, stdReq)
		if err != nil {
			return
		}
		start := tr.msgStart
		body, enc, berr := readBodyCappedEncoding(resp.Body, c.mgr.cfg.MaxBodyBytes, resp.Header.Get("Content-Encoding"))
		end := h.lastSeen
		if start.IsZero() {
			start = end
		}
		_ = resp.Body.Close()

		rev := &responseEvent{
			statusCode:   resp.StatusCode,
			reason:       resp.Status,
			header:       flattenHeader(resp.Header),
			body:         body,
			bodyEnc:      enc,
			resp:         resp,
			start:        start,
			end:          end,
			responseSize: int64(len(body)) + headerSize(resp.Header),
		}
		c.mgr.emit(c, req, rev)
		if berr != nil && !errors.Is(berr, errBodyTruncated) {
			return
		}
	}
}

// takeRequest returns the next pending request event. In HTTP/1.x a request is
// fully sent (and therefore already pushed here) before the response begins, so
// the non-blocking path almost always succeeds. It falls back to a short bounded
// wait rather than blocking indefinitely, so the response goroutine can finish.
func (c *connection) takeRequest() *requestEvent {
	select {
	case r, ok := <-c.pendingReqs:
		if !ok {
			return nil
		}
		return r
	case <-c.reqDone:
		select {
		case r, ok := <-c.pendingReqs:
			if ok {
				return r
			}
		default:
		}
		return nil
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}

func (c *connection) drainPending() {
	for {
		select {
		case r, ok := <-c.pendingReqs:
			if !ok {
				return
			}
			c.mgr.emit(c, r, nil)
		default:
			return
		}
	}
}

func (c *connection) recordTLSFromHalf(h *halfStream, peek []byte) {
	sni, ver := parseSNI(peek)
	c.mu.Lock()
	c.isTLS = true
	if sni != "" {
		c.sni = sni
	}
	if ver != "" {
		c.tlsVersion = ver
	}
	if h.isClient {
		c.client = srcEndpointOf(h.direction)
		c.clientSet = true
	}
	c.mu.Unlock()
}

// shutdown waits for both halves, emits any requests that never got a response,
// and — for TLS streams that produced no HTTP transaction — emits a synthetic
// encrypted-session record so the SNI/metadata still appears in the UI.
func (c *connection) shutdown() {
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	// Drain unpaired requests.
	for {
		select {
		case req, ok := <-c.pendingReqs:
			if !ok {
				goto after
			}
			c.mgr.emit(c, req, nil)
		default:
			goto after
		}
	}
after:
	c.mu.Lock()
	isTLS := c.isTLS
	noHTTP := c.txEmitted == 0
	sni := c.sni
	ver := c.tlsVersion
	srcIP, srcPort := c.srcIP, c.srcPort
	dstIP, dstPort := c.dstIP, c.dstPort
	first := c.tlsFirst
	c.mu.Unlock()
	if isTLS && noHTTP {
		c.mgr.emitTLSSession(c, sni, ver, srcIP, srcPort, dstIP, dstPort, first)
	}
}

// emit builds a transaction from a request/response pair and hands it to the sink.
func (m *connManager) emit(c *connection, req *requestEvent, resp *responseEvent) {
	tx := &model.HTTPTx{
		ID:       m.nextTxID(),
		StreamID: int64(hashKey(c.key)),
	}
	c.mu.Lock()
	tx.IsTLS = c.isTLS
	tx.SNI = c.sni
	tx.TLSVersion = c.tlsVersion
	c.mu.Unlock()

	if req != nil {
		tx.StartTime = req.start
		tx.Method = req.method
		tx.Host = req.host
		tx.URL = req.url
		tx.FullURL = req.fullURL
		tx.HTTPVersion = req.version
		tx.RequestHeader = req.header
		tx.RequestBody = model.BodyRef{Inline: len(req.body) > 0, Data: req.body, Encoding: req.bodyEnc, Length: int64(len(req.body))}
		tx.RequestSize = req.requestSize
		tx.SrcIP = req.srcIP
		tx.SrcPort = req.srcPort
		tx.DstIP = req.dstIP
		tx.DstPort = req.dstPort
	}
	if resp != nil {
		tx.StatusCode = resp.statusCode
		tx.ReasonPhrase = resp.reason
		tx.ResponseHeader = resp.header
		tx.ResponseBody = model.BodyRef{Inline: len(resp.body) > 0, Data: resp.body, Encoding: resp.bodyEnc, Length: int64(len(resp.body))}
		tx.ResponseSize = resp.responseSize
		tx.ContentType = resp.header["Content-Type"]
		if !resp.end.IsZero() {
			tx.EndTime = resp.end
		}
	}
	if !tx.StartTime.IsZero() && !tx.EndTime.IsZero() {
		tx.DurationMs = tx.EndTime.Sub(tx.StartTime).Milliseconds()
	}

	m.sink.AddTransaction(tx)
	atomic.AddInt64(&m.stats.Transactions, 1)
	c.mu.Lock()
	c.txEmitted++
	c.mu.Unlock()
}

// emitTLSSession emits a synthetic transaction representing a TLS stream whose
// encrypted contents cannot be shown (no key log). It carries SNI/version so the
// session still appears in the list.
func (m *connManager) emitTLSSession(c *connection, sni, version, srcIP string, srcPort int, dstIP string, dstPort int, first time.Time) {
	tx := &model.HTTPTx{
		ID:         m.nextTxID(),
		StreamID:   int64(hashKey(c.key)),
		IsTLS:      true,
		SNI:        sni,
		TLSVersion: version,
		Host:       sni,
		URL:        "(encrypted)",
		StartTime:  first,
		SrcIP:      srcIP,
		SrcPort:    srcPort,
		DstIP:      dstIP,
		DstPort:    dstPort,
	}
	m.sink.AddTransaction(tx)
	atomic.AddInt64(&m.stats.Transactions, 1)
	atomic.AddInt64(&m.stats.TLSSessions, 1)
	c.mu.Lock()
	c.txEmitted++
	c.mu.Unlock()
}

// ---------- helpers ----------

type timedReader struct {
	s        *stream
	msgStart time.Time
}

func (t *timedReader) Read(p []byte) (int, error) {
	n, err := t.s.Read(p)
	if n > 0 && t.msgStart.IsZero() {
		t.msgStart = t.s.lastChunkSeen
	}
	return n, err
}

func (t *timedReader) reset() { t.msgStart = time.Time{} }

var errBodyTruncated = errors.New("body truncated at cap")

// readBodyCappedEncoding reads an HTTP message body, transparently decompressing
// gzip/deflate, but caps the stored bytes at max. It returns the decoded bytes.
func readBodyCappedEncoding(r io.Reader, max int64, encoding string) ([]byte, string, error) {
	// Decompress gzip/deflate if needed.
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	var reader io.Reader = r
	switch {
	case strings.Contains(encoding, "gzip"):
		gr, err := newGzipReader(r)
		if err != nil {
			return nil, encoding, err
		}
		defer gr.Close()
		reader = gr
	case strings.Contains(encoding, "deflate"):
		reader = newFlateReader(r)
	}
	data, err := readAllCapped(reader, max)
	if err != nil && !errors.Is(err, errBodyTruncated) {
		return data, encoding, err
	}
	return data, encoding, err
}

func readAllCapped(r io.Reader, max int64) ([]byte, error) {
	buf := make([]byte, 0, 32*1024)
	tmp := make([]byte, 32*1024)
	var total int64
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			if total+int64(n) > max {
				buf = append(buf, tmp[:max-total]...)
				return buf, errBodyTruncated
			}
			buf = append(buf, tmp[:n]...)
			total += int64(n)
		}
		if errors.Is(err, io.EOF) {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
	}
}

func flattenHeader(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func headerSize(h http.Header) int64 {
	var n int64
	for k, v := range h {
		n += int64(len(k)) + 4
		for _, vv := range v {
			n += int64(len(vv)) + 2
		}
	}
	return n
}

func requestURL(req *http.Request) string {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, req.URL.RequestURI())
}

func looksLikeRequest(peek []byte) bool {
	methods := []string{"GET ", "POST", "PUT ", "DELE", "HEAD", "OPTI", "PATC", "TRAC", "CONN"}
	if len(peek) < 4 {
		return false
	}
	for _, m := range methods {
		if bytes.HasPrefix(peek, []byte(m)) {
			// Ensure the 4th byte of POST/PUT/DELETE is a space after method.
			return true
		}
	}
	return false
}

func looksLikeResponse(peek []byte) bool {
	return bytes.HasPrefix(peek, []byte("HTTP/"))
}

func looksLikeTLS(peek []byte) bool {
	return len(peek) >= 3 && peek[0] == 0x16 && peek[1] == 0x03
}

func srcEndpointOf(direction string) string {
	if i := strings.Index(direction, "->"); i >= 0 {
		return direction[:i]
	}
	return direction
}

func portOfDirection(direction string) int {
	src := srcEndpointOf(direction)
	if i := strings.LastIndex(src, ":"); i >= 0 {
		var p int
		fmt.Sscanf(src[i+1:], "%d", &p)
		return p
	}
	return 0
}

func netIPString(b []byte) string {
	return net.IP(b).String()
}

// hashKey converts a connection key to a stable positive int64.
func hashKey(s string) uint32 {
	// FNV-1a 32-bit.
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}
