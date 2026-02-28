// stress is a TCP stress tester for the pico HTTP server.
// It exercises connection edge cases that have caused crashes (see SEQSBUG_REPORT.md).
//
// Usage:
//
//	go run ./cmd/stress <addr>
//	go run ./cmd/stress -n 100 -c 10 -pattern all 192.168.1.99:80
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type stats struct {
	attempted atomic.Int64
	succeeded atomic.Int64
	failed    atomic.Int64
	timeouts  atomic.Int64
}

func (s *stats) String() string {
	return fmt.Sprintf("attempted=%d succeeded=%d failed=%d timeouts=%d",
		s.attempted.Load(), s.succeeded.Load(), s.failed.Load(), s.timeouts.Load())
}

type pattern struct {
	name string
	fn   func(addr string, s *stats, n, concurrency int)
}

var patterns = []pattern{
	{"rapid-cycle", rapidCycle},
	{"syn-flood", synFlood},
	{"port-reuse", portReuse},
	{"slow-client", slowClient},
	{"rapid-rst", rapidRST},
}

func main() {
	n := flag.Int("n", 50, "iterations per pattern")
	c := flag.Int("c", 5, "concurrency per pattern")
	pat := flag.String("pattern", "all", "pattern to run (rapid-cycle, syn-flood, port-reuse, slow-client, rapid-rst, all)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <addr>\n\nStress test a pico HTTP server.\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nPatterns:\n")
		fmt.Fprintf(os.Stderr, "  rapid-cycle   Rapid connect→request→close cycling\n")
		fmt.Fprintf(os.Stderr, "  syn-flood     Half-open connections (connect, never send)\n")
		fmt.Fprintf(os.Stderr, "  port-reuse    Reuse source port across connections\n")
		fmt.Fprintf(os.Stderr, "  slow-client   Byte-by-byte HTTP request\n")
		fmt.Fprintf(os.Stderr, "  rapid-rst     Connect, partial send, immediate RST\n")
		fmt.Fprintf(os.Stderr, "  all           Run all patterns sequentially\n")
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	addr := flag.Arg(0)
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}

	// Verify connectivity.
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach %s: %v\n", addr, err)
		os.Exit(1)
	}
	conn.Close()
	fmt.Printf("target: %s\n\n", addr)

	start := time.Now()
	var toRun []pattern
	if *pat == "all" {
		toRun = patterns
	} else {
		for _, p := range patterns {
			if p.name == *pat {
				toRun = append(toRun, p)
			}
		}
		if len(toRun) == 0 {
			fmt.Fprintf(os.Stderr, "unknown pattern: %s\n", *pat)
			os.Exit(1)
		}
	}

	for _, p := range toRun {
		fmt.Printf("--- %s (n=%d c=%d) ---\n", p.name, *n, *c)
		var s stats
		p.fn(addr, &s, *n, *c)
		fmt.Printf("    %s\n\n", &s)
	}
	fmt.Printf("done in %s\n", time.Since(start).Round(time.Millisecond))
}

// rapidCycle opens a TCP connection, sends a full HTTP/1.0 GET, reads
// the response, and closes. Repeats in a tight loop. Saturates the
// server's 10-connection pool and exercises accept/recycle.
func rapidCycle(addr string, s *stats, n, concurrency int) {
	run(concurrency, n, func() {
		s.attempted.Add(1)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			s.failed.Add(1)
			countTimeout(err, s)
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte("GET / HTTP/1.0\r\nHost: pico\r\n\r\n"))
		if err != nil {
			s.failed.Add(1)
			countTimeout(err, s)
			return
		}
		buf := make([]byte, 4096)
		totalRead := 0
		for {
			nr, err := conn.Read(buf)
			totalRead += nr
			if err != nil {
				break
			}
		}
		if totalRead > 0 {
			s.succeeded.Add(1)
		} else {
			s.failed.Add(1)
		}
	})
}

// synFlood opens TCP connections but never sends any data. The server's
// 8s read deadline will fire, consuming pool slots until timeout. This is
// the exact path that led to the SYN-retransmit crash — the server cycles
// through Open→SynRcvd→timeout→Close→Abort for each stuck connection.
func synFlood(addr string, s *stats, n, concurrency int) {
	// Hold connections open to exhaust the pool.
	var mu sync.Mutex
	var held []net.Conn
	run(concurrency, n, func() {
		s.attempted.Add(1)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			s.failed.Add(1)
			countTimeout(err, s)
			return
		}
		s.succeeded.Add(1)
		mu.Lock()
		held = append(held, conn)
		mu.Unlock()
	})
	// Hold for a bit, then release all at once.
	fmt.Printf("    holding %d half-open connections for 3s...\n", len(held))
	time.Sleep(3 * time.Second)
	for _, c := range held {
		c.Close()
	}
}

// portReuse reuses the same source port across sequential connections.
// This simulates the crash scenario: a retransmitted SYN from the same
// (ip, port) pair arriving on an already-established connection.
func portReuse(addr string, s *stats, n, _ int) {
	// Find a free local port to reuse.
	tmp, err := net.Dial("tcp", addr)
	if err != nil {
		s.attempted.Add(1)
		s.failed.Add(1)
		return
	}
	localPort := tmp.LocalAddr().(*net.TCPAddr).Port
	tmp.Close()
	time.Sleep(50 * time.Millisecond) // Let TIME_WAIT settle a bit.

	localAddr := &net.TCPAddr{Port: localPort}
	dialer := net.Dialer{
		LocalAddr: localAddr,
		Timeout:   2 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			c.Control(func(fd uintptr) {
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			return opErr
		},
	}

	// Sequential: connect from same port, do request, close, repeat.
	for i := range n {
		s.attempted.Add(1)
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			s.failed.Add(1)
			countTimeout(err, s)
			// Port might be in TIME_WAIT, wait and retry.
			time.Sleep(200 * time.Millisecond)
			continue
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte(fmt.Sprintf("GET /toggle-led?callsign=S%d HTTP/1.0\r\n\r\n", i)))
		if err != nil {
			conn.Close()
			s.failed.Add(1)
			countTimeout(err, s)
			continue
		}
		io.ReadAll(conn)
		conn.Close()
		s.succeeded.Add(1)
		time.Sleep(50 * time.Millisecond)
	}
}

// slowClient sends an HTTP request one byte at a time with small delays.
// Tests the server's read-deadline and partial-read buffering under pressure.
func slowClient(addr string, s *stats, n, concurrency int) {
	req := []byte("GET / HTTP/1.0\r\nHost: pico\r\nUser-Agent: slow\r\n\r\n")
	run(concurrency, n, func() {
		s.attempted.Add(1)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			s.failed.Add(1)
			countTimeout(err, s)
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		for _, b := range req {
			_, err := conn.Write([]byte{b})
			if err != nil {
				s.failed.Add(1)
				countTimeout(err, s)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		buf := make([]byte, 4096)
		total := 0
		for {
			nr, err := conn.Read(buf)
			total += nr
			if err != nil {
				break
			}
		}
		if total > 0 {
			s.succeeded.Add(1)
		} else {
			s.failed.Add(1)
		}
	})
}

// rapidRST connects, sends a partial HTTP request, then immediately
// closes the connection causing a RST. Exercises the server's RST
// handling in both pre-established and established states.
func rapidRST(addr string, s *stats, n, concurrency int) {
	run(concurrency, n, func() {
		s.attempted.Add(1)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			s.failed.Add(1)
			countTimeout(err, s)
			return
		}
		// Send partial request (no \r\n\r\n terminator).
		conn.Write([]byte("GET / HTTP"))
		// Set linger to 0 to force RST on close instead of FIN.
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		conn.Close()
		s.succeeded.Add(1)
	})
}

// run executes fn n times across the given number of goroutines.
func run(concurrency, n int, fn func()) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fn()
		}()
	}
	wg.Wait()
}

func countTimeout(err error, s *stats) {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		s.timeouts.Add(1)
	}
}
