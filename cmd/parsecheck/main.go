// Command parsecheck reads a pcap/pcapng and prints HTTP/TLS summary — used to
// verify reassembly and pairing without spinning up the full server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sort"
	"time"

	"pcap-http-viewer/internal/parser"
	"pcap-http-viewer/internal/storage"
)

func main() {
	path := flag.String("f", "", "pcap/pcapng file")
	top := flag.Int("n", 20, "show first N transactions")
	flag.Parse()
	if *path == "" {
		log.Fatal("usage: parsecheck -f file.pcapng [-n 20]")
	}
	start := time.Now()
	st, err := storage.New()
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	st.SetFileName(*path)

	p := parser.New(*path, st, parser.Config{})
	if err := p.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
	stats := p.Stats()

	md := st.Metadata()
	fmt.Printf("packets=%d  tx=%d  tlsTxs=%d  errors=%d  streams=%d  elapsed=%s\n",
		stats.Packets, st.Count(), stats.TLSSessions, stats.Errors, len(st.StreamSummaries()), time.Since(start).Round(time.Millisecond))

	methods := map[string]int{}
	hosts := map[string]int{}
	statuses := map[int]int{}
	sni := map[string]int{}
	for _, m := range md {
		if m.IsTLS {
			sni[m.SNI]++
			continue
		}
		methods[m.Method]++
		if m.Host != "" {
			hosts[m.Host]++
		}
		statuses[m.StatusCode]++
	}
	fmt.Println("\nmethods:", methods)
	fmt.Println("statuses:", statuses)
	fmt.Println("\nplaintext hosts:")
	for _, p := range topN(hosts, 8) {
		fmt.Printf("  %4d  %s\n", p.v, p.k)
	}
	fmt.Println("\nTLS SNI:")
	for _, p := range topN(sni, 15) {
		fmt.Printf("  %4d  %s\n", p.v, p.k)
	}

	n := *top
	if n > len(md) {
		n = len(md)
	}
	fmt.Printf("\nfirst %d transactions:\n", n)
	for i := 0; i < n; i++ {
		m := md[i]
		if m.IsTLS {
			fmt.Printf("  [%d] TLS sni=%s tlsver? (see detail)\n", m.ID, m.SNI)
			continue
		}
		fmt.Printf("  [%d] %s %s%s -> %d  %dms req=%d resp=%d\n",
			m.ID, m.Method, m.Host, m.URL, m.StatusCode, m.DurationMs, m.ReqSize, m.RespSize)
	}
}

func topN(m map[string]int, n int) []pair {
	p := make([]pair, 0, len(m))
	for k, v := range m {
		p = append(p, pair{k, v})
	}
	sort.Slice(p, func(i, j int) bool { return p[i].v > p[j].v })
	if n < len(p) {
		p = p[:n]
	}
	return p
}

type pair struct {
	k string
	v int
}
