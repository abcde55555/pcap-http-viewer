// Command pcap-http-viewer starts a local web server that parses a pcap/pcapng
// file and presents HTTP transactions (left request / right response) with
// filtering and sensitive-data scanning. The UI is a single embedded HTML page;
// the server only listens on 127.0.0.1 and opens the default browser.
package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"pcap-http-viewer/internal/app"
	"pcap-http-viewer/internal/web"
)

//go:embed web rules/default.yaml
var assets embed.FS

func main() {
	file := flag.String("f", "", "pcap/pcapng file to open on startup (optional)")
	port := flag.Int("p", 0, "fixed port (default: random)")
	noBrowser := flag.Bool("no-browser", false, "don't open the browser")
	flag.Parse()

	// Per-user editable rules file (created on first save).
	userRules := filepath.Join(userConfigDir(), "sensitive-rules.yaml")

	defaultRules, err := assets.ReadFile("rules/default.yaml")
	if err != nil {
		log.Fatalf("read embedded rules: %v", err)
	}

	application, err := app.New(defaultRules, userRules)
	if err != nil {
		log.Fatalf("init app: %v", err)
	}

	srv := web.NewServer(application, assets)
	addr := "127.0.0.1:0"
	if *port > 0 {
		addr = fmt.Sprintf("127.0.0.1:%d", *port)
	}
	url, httpSrv, err := srv.ListenAddr(addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer httpSrv.Close()

	fmt.Printf("\n  PCAP HTTP Viewer\n")
	fmt.Printf("  ===============\n")
	fmt.Printf("  URL:   %s\n", url)
	fmt.Printf("  Rules: %s (user overrides)\n\n", userRules)
	if *file != "" {
		abs, _ := filepath.Abs(*file)
		fmt.Printf("Opening %s ...\n", abs)
		go func() {
			time.Sleep(300 * time.Millisecond)
			if err := application.Open(abs); err != nil {
				log.Printf("open: %v", err)
			}
		}()
	}
	if !*noBrowser {
		_ = web.OpenBrowser(url)
	}
	log.Printf("server on %s (Ctrl+C to quit)", url)
	select {}
}

func userConfigDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		d := filepath.Join(dir, "pcap-http-viewer")
		_ = os.MkdirAll(d, 0o755)
		return d
	}
	dir, _ := os.MkdirTemp("", "pcapview-*")
	return dir
}
