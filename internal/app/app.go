// Package app ties parsing, storage and plugins together.
package app

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"pcap-http-viewer/internal/model"
	"pcap-http-viewer/internal/parser"
	"pcap-http-viewer/internal/plugins"
	"pcap-http-viewer/internal/storage"
)

// Progress is reported while parsing.
type Progress struct {
	Phase        string `json:"phase"` // "parsing" | "scanning" | "done" | "error"
	Packets      int64  `json:"packets"`
	Transactions int64  `json:"transactions"`
	TLSSessions  int64  `json:"tlsSessions"`
	Streams      int    `json:"streams"`
	Percent      int    `json:"percent"` // -1 if unknown
	ElapsedMs    int64  `json:"elapsedMs"`
	Message      string `json:"message,omitempty"`
}

// App is the long-lived application service.
type App struct {
	mu sync.RWMutex

	store    *storage.Store
	registry *plugins.Registry
	sensitive *plugins.SensitiveEngine

	rulesPath string // path to a user-editable rules file (if saved)

	currentFile   string
	parsing       bool
	scanRunning   bool
	rescanPending bool
	progress      Progress
	listeners     map[int]chan Progress
	listenerSeq   int
	cancel        context.CancelFunc
}

// New creates the app and loads the built-in default rules.
func New(defaultRules []byte, userRulesPath string) (*App, error) {
	reg := plugins.NewRegistry()

	// Load defaults; user overrides (if present) are appended/replaced.
	rules, err := plugins.LoadRules(defaultRules)
	if err != nil {
		return nil, fmt.Errorf("load default rules: %w", err)
	}
	if userRulesPath != "" {
		if user, err := plugins.LoadRulesFile(userRulesPath); err == nil && len(user) > 0 {
			rules = mergeRules(rules, user)
		}
	}
	engine, errs := plugins.NewSensitiveEngine(rules)
	if len(errs) > 0 {
		// Defaults must always compile; log but continue.
		for _, e := range errs {
			fmt.Printf("rule compile warning: %v\n", e)
		}
	}
	reg.Register(engine)

	st, err := storage.New()
	if err != nil {
		return nil, err
	}
	return &App{
		store:     st,
		registry:  reg,
		sensitive: engine,
		rulesPath: userRulesPath,
		listeners: make(map[int]chan Progress),
	}, nil
}

// Store exposes the underlying store (for API handlers).
func (a *App) Store() *storage.Store { return a.store }

// Sensitive exposes the sensitive engine (for rule-management API).
func (a *App) Sensitive() *plugins.SensitiveEngine { return a.sensitive }

// CurrentFile returns the path of the loaded capture (if any).
func (a *App) CurrentFile() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.currentFile
}

// IsParsing reports whether a parse is in progress.
func (a *App) IsParsing() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.parsing
}

// Subscribe returns a channel that receives progress updates. Call unsubscribe
// when done.
func (a *App) Subscribe() (<-chan Progress, func()) {
	ch := make(chan Progress, 16)
	a.mu.Lock()
	a.listenerSeq++
	id := a.listenerSeq
	a.listeners[id] = ch
	snapshot := a.progress
	a.mu.Unlock()
	select {
	case ch <- snapshot:
	default:
	}
	return ch, func() {
		a.mu.Lock()
		if c, ok := a.listeners[id]; ok {
			close(c)
			delete(a.listeners, id)
		}
		a.mu.Unlock()
	}
}

func (a *App) broadcast(p Progress) {
	a.mu.Lock()
	a.progress = p
	for _, ch := range a.listeners {
		select {
		case ch <- p:
		default:
		}
	}
	a.mu.Unlock()
}

// Open parses a pcap/pcapng file and runs plugins. It runs asynchronously;
// track progress via Subscribe.
func (a *App) Open(path string) error {
	a.mu.Lock()
	if a.parsing {
		a.mu.Unlock()
		return fmt.Errorf("a parse is already in progress")
	}
	a.parsing = true
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.mu.Unlock()

	go a.run(ctx, path)
	return nil
}

func (a *App) run(ctx context.Context, path string) {
	start := time.Now()
	defer func() {
		a.mu.Lock()
		a.parsing = false
		a.mu.Unlock()
	}()

	a.broadcast(Progress{Phase: "parsing", Message: "读取并重组 TCP 流..."})

	// Replace the store for the new file.
	newStore, err := storage.New()
	if err != nil {
		a.broadcast(Progress{Phase: "error", Message: err.Error()})
		return
	}
	a.mu.Lock()
	old := a.store
	a.store = newStore
	a.currentFile = path
	newStore.SetFileName(filepath.Base(path))
	a.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	p := parser.New(path, newStore, parser.Config{})

	// Progress ticker while parsing.
	tickDone := make(chan struct{})
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s := p.Stats()
				a.broadcast(Progress{
					Phase: "parsing", Packets: s.Packets,
					Transactions: s.Transactions, TLSSessions: s.TLSSessions,
					Percent: -1, ElapsedMs: time.Since(start).Milliseconds(),
				})
			case <-tickDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := p.Run(ctx); err != nil {
		close(tickDone)
		a.broadcast(Progress{Phase: "error", Message: err.Error()})
		return
	}
	close(tickDone)
	st := p.Stats()
	// Sensitive-info scanning is opt-in: do not run it automatically on parse.
	a.broadcast(Progress{
		Phase: "done", Packets: st.Packets, Transactions: st.Transactions,
		TLSSessions: st.TLSSessions, Streams: newStore.Count(), Percent: 100,
		ElapsedMs: time.Since(start).Milliseconds(),
		Message: fmt.Sprintf("完成: %d 个数据包, %d 个会话", st.Packets, newStore.Count()),
	})
}

// runPlugins executes all plugins across all transactions using a worker pool.
func (a *App) runPlugins(store *storage.Store) {
	txs := make([]*model.HTTPTx, 0, store.Count())
	store.ForEach(func(tx *model.HTTPTx) { txs = append(txs, tx) })

	results := make([][]model.Finding, len(txs))
	jobs := make(chan int, len(txs))
	for i := range txs {
		jobs <- i
	}
	close(jobs)

	var workers int64 = 8
	var wg sync.WaitGroup
	for w := 0; w < int(workers); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				tx := txs[i]
				results[i] = a.registry.Run(tx, storeBodyReader{store: store})
			}
		}()
	}
	wg.Wait()

	// Attach findings.
	byID := make(map[int64][]model.Finding, len(txs))
	for i, tx := range txs {
		if len(results[i]) > 0 {
			byID[tx.ID] = results[i]
		}
	}
	store.ReplaceFindings(byID)
}

// UpdateRules replaces the active rule set. It does NOT scan automatically;
// call ScanNow to apply. Scanning is a user-initiated action.
func (a *App) UpdateRules(rules []*plugins.Rule) []error {
	errs := a.sensitive.SetRules(rules)
	if len(errs) > 0 {
		return errs
	}
	if a.rulesPath != "" {
		_ = plugins.SaveRulesFile(a.rulesPath, rules)
	}
	return nil
}

// ScanNow runs the active plugins over the current capture. It is serialized
// and coalesced: repeated calls while a scan is running collapse into one
// follow-up scan.
func (a *App) ScanNow() error {
	a.mu.Lock()
	if a.store.Count() == 0 {
		a.mu.Unlock()
		return fmt.Errorf("no capture loaded")
	}
	if a.parsing {
		a.mu.Unlock()
		return fmt.Errorf("parsing in progress")
	}
	if a.scanRunning {
		a.rescanPending = true
		a.mu.Unlock()
		return nil
	}
	a.scanRunning = true
	a.mu.Unlock()

	go func() {
		for {
			a.mu.Lock()
			store := a.store
			a.mu.Unlock()
			a.broadcast(Progress{Phase: "scanning", Message: "扫描敏感信息…", Streams: store.Count()})
			a.runPlugins(store)
			a.broadcast(Progress{Phase: "scan-done", Streams: store.Count(),
				Message: fmt.Sprintf("敏感信息扫描完成 (%d 个会话)", store.Count())})
			a.mu.Lock()
			if a.rescanPending {
				a.rescanPending = false
				a.mu.Unlock()
				continue
			}
			a.scanRunning = false
			a.mu.Unlock()
			return
		}
	}()
	return nil
}

// storeBodyReader implements plugins.BodyReader over a *storage.Store.
type storeBodyReader struct{ store *storage.Store }

func (b storeBodyReader) ReadBody(tx *model.HTTPTx, side string) ([]byte, error) {
	ref := tx.RequestBody
	if side == "resp" {
		ref = tx.ResponseBody
	}
	var n int64 = ref.Length
	if n > 1<<20 {
		n = 1 << 20 // plugins only need the first 1 MiB
	}
	if n <= 0 {
		return nil, nil
	}
	return b.store.ReadBody(tx.ID, side, 0, n)
}

// mergeRules returns the union of defaults and user rules, with user rules
// overriding by ID.
func mergeRules(base, override []*plugins.Rule) []*plugins.Rule {
	byID := make(map[string]*plugins.Rule, len(base)+len(override))
	for _, r := range base {
		byID[r.ID] = r
	}
	for _, r := range override {
		byID[r.ID] = r
	}
	out := make([]*plugins.Rule, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	return out
}
