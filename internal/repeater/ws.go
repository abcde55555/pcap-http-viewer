package repeater

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// IsWSUpgrade reports whether a raw HTTP request is a WebSocket handshake.
// Some copied/captured handshakes omit the Upgrade/Connection headers but still
// carry Sec-WebSocket-Key/Version; the dialer adds the former automatically.
func IsWSUpgrade(raw []byte) bool {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return false
	}
	if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return true
	}
	return strings.EqualFold(req.Header.Get("Sec-Websocket-Version"), "13") &&
		req.Header.Get("Sec-Websocket-Key") != ""
}

// WSConn is a live WebSocket connection between the browser and a target host.
// Messages from the browser are forwarded to the target; messages from the
// target are pushed back as JSON frames so the UI can log them in real time.
type WSConn struct {
	ID      string `json:"id"`
	Target  string `json:"target"`
	created time.Time

	toTarget *websocket.Conn
	mu       sync.Mutex
	closed   bool
	send     chan WSEvent // events pushed to the browser

	log   []WSEvent // recent events, replayed to late SSE subscribers
	logMu sync.Mutex
	done  chan struct{}
}

// WSEvent is a single frame or lifecycle event sent to the UI.
type WSEvent struct {
	Type      string `json:"type"` // "open","message","close","error","sent"
	Direction string `json:"dir,omitempty"` // "sent" | "recv"
	Opcode    string `json:"op,omitempty"` // "text" | "binary" | "close" | "ping" | "pong"
	Data      string `json:"data,omitempty"` // text as-is, binary as base64 (see Binary)
	Binary    bool   `json:"binary,omitempty"`
	Time      int64  `json:"t"`
	Message   string `json:"message,omitempty"`
}

var (
	wsMu    sync.Mutex
	wsConns = make(map[string]*WSConn)
)

// WSConnect opens a WebSocket to target described by a raw upgrade request.
// Returns a WSConn. The browser then reads events via the SSE endpoint and
// sends frames via /api/repeater/ws/send.
func WSConnect(scheme, host string, raw []byte, opts Options) (*WSConn, error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = req.Host
	}
	wsScheme := "ws"
	switch strings.ToLower(scheme) {
	case "wss", "https":
		wsScheme = "wss"
	case "ws", "http":
		wsScheme = "ws"
	default:
		// Auto: wss if target is port 443, otherwise ws.
		if h, p, err := net.SplitHostPort(host); err == nil && p == "443" {
			_ = h
			wsScheme = "wss"
		}
	}
	targetURL := &url.URL{Scheme: wsScheme, Host: host, Path: req.URL.Path, RawQuery: req.URL.RawQuery}

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = opts.timeout()
	if opts.InsecureTLS {
		if dialer.TLSClientConfig == nil {
			dialer.TLSClientConfig = &tls.Config{}
		}
		dialer.TLSClientConfig.InsecureSkipVerify = true
	}
	if opts.UpstreamProxy != "" {
		if pu, perr := url.Parse(opts.UpstreamProxy); perr == nil {
			dialer.Proxy = http.ProxyURL(pu)
		}
	}
	// Build request headers from the raw request (minus hop/framing/ws keys we
	// manage ourselves).
	reqHeader := http.Header{}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "upgrade", "connection", "sec-websocket-key", "sec-websocket-version",
			"sec-websocket-extensions", "sec-websocket-protocol", "content-length", "host":
			continue
		}
		reqHeader[k] = vs
	}
	if sub := req.Header.Get("Sec-WebSocket-Protocol"); sub != "" {
		dialer.Subprotocols = splitCSV(sub)
	}

	conn, resp, err := dialer.Dial(targetURL.String(), reqHeader)
	if err != nil {
		return nil, err
	}
	id := newWSID()
	c := &WSConn{
		ID: id, Target: targetURL.String(), created: time.Now(),
		toTarget: conn,
		send:     make(chan WSEvent, 256),
		done:     make(chan struct{}),
	}
	wsMu.Lock()
	wsConns[id] = c
	wsMu.Unlock()

	c.push(WSEvent{Type: "open", Time: time.Now().UnixMilli(),
		Message: "已连接 " + targetURL.String() + formatWSResp(resp)})

	// Pump target -> browser.
	go c.readPump()
	return c, nil
}

func formatWSResp(r *http.Response) string {
	if r == nil {
		return ""
	}
	return " (" + r.Status + ")"
}

func (c *WSConn) readPump() {
	defer c.Close()
	for {
		msgType, data, err := c.toTarget.ReadMessage()
		if err != nil {
			c.push(WSEvent{Type: "error", Time: time.Now().UnixMilli(), Message: err.Error()})
			return
		}
		op := "text"
		binary := false
		switch msgType {
		case websocket.TextMessage:
			op = "text"
		case websocket.BinaryMessage:
			op = "binary"
			binary = true
		case websocket.CloseMessage:
			op = "close"
			c.push(WSEvent{Type: "close", Time: time.Now().UnixMilli(), Message: string(data)})
			return
		case websocket.PingMessage:
			op = "ping"
		case websocket.PongMessage:
			op = "pong"
		}
		ev := WSEvent{Type: "message", Direction: "recv", Opcode: op, Binary: binary, Time: time.Now().UnixMilli()}
		if binary {
			ev.Data = b64(data)
		} else {
			ev.Data = string(data)
		}
		c.push(ev)
	}
}

// Send pushes one frame to the target.
func (c *WSConn) Send(text string, binary bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	t := websocket.TextMessage
	if binary {
		t = websocket.BinaryMessage
	}
	err := c.toTarget.WriteMessage(t, []byte(text))
	if err != nil {
		return err
	}
	op := "text"
	if binary {
		op = "binary"
	}
	c.push(WSEvent{Type: "sent", Direction: "sent", Opcode: op, Binary: binary, Data: text, Time: time.Now().UnixMilli()})
	return nil
}

// Events returns the event channel (used by SSE).
func (c *WSConn) Events() <-chan WSEvent { return c.send }

// Close terminates the connection.
func (c *WSConn) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	_ = c.toTarget.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	_ = c.toTarget.Close()
	c.push(WSEvent{Type: "close", Time: time.Now().UnixMilli(), Message: "连接已关闭"})
	close(c.send)
	// Keep the connection record around briefly so a late SSE subscriber can
	// still read the buffered events (including any error). Garbage-collect
	// after a short delay.
	go func() {
		time.Sleep(30 * time.Second)
		wsMu.Lock()
		if cur := wsConns[c.ID]; cur == c {
			delete(wsConns, c.ID)
		}
		wsMu.Unlock()
	}()
}

func (c *WSConn) push(ev WSEvent) {
	c.logMu.Lock()
	c.log = append(c.log, ev)
	if len(c.log) > 500 {
		c.log = c.log[len(c.log)-500:]
	}
	c.logMu.Unlock()
	select {
	case c.send <- ev:
	default:
	}
}

// WSGet returns a live connection by id.
func WSGet(id string) *WSConn {
	wsMu.Lock()
	defer wsMu.Unlock()
	return wsConns[id]
}

// WSClose closes a connection by id.
func WSClose(id string) {
	if c := WSGet(id); c != nil {
		c.Close()
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func newWSID() string {
	return "ws" + randID(10)
}

// WSServeEvents streams events for one connection to the browser as SSE data.
// It first replays any buffered events (so a subscriber that attaches right
// after a failed dial still sees the error), then streams live until closed.
func WSServeEvents(ctx context.Context, c *WSConn, write func([]byte) error) {
	// Replay buffered events.
	c.logMu.Lock()
	hist := make([]WSEvent, len(c.log))
	copy(hist, c.log)
	c.logMu.Unlock()
	for _, ev := range hist {
		b, _ := json.Marshal(ev)
		if err := write(b); err != nil {
			return
		}
	}

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-c.Events():
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			if err := write(b); err != nil {
				return
			}
		case <-tick.C:
			if err := write([]byte(`{"type":"ping"}`)); err != nil {
				return
			}
		}
	}
}
