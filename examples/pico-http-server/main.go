//go:build rp2040 || rp2350

package main

// WARNING: default -scheduler=cores unsupported, compile with -scheduler=tasks set!

import (
	"bytes"
	"log/slog"
	"machine"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	_ "embed"

	"github.com/soypat/lan8720"
	"github.com/soypat/lan8720/examples/lannet"
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/http/httphi"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/phy"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/x/xnet"
	pio "github.com/tinygo-org/pio/rp2-pio"
	"github.com/tinygo-org/pio/rp2-pio/piolib"
)

const (
	linkmode   = phy.Link100FDX
	listenPort = 80
	loopSleep  = 5 * time.Millisecond
	maxConns   = 6
	icmpQueue  = 2 // set to zero to disable ICMP.

	// reqHdrBuf bounds the request header a single exchange may hold; a request
	// whose header exceeds it is failed rather than accumulated.
	reqHdrBuf = 1024
	// respHdrBuf is the minimum room reserved for staged response headers.
	// Unused request header memory is reused on top of it.
	respHdrBuf = 128
	// connTimeout bounds a whole exchange: the router's read loop backs off on an
	// idle connection forever otherwise.
	connTimeout = 8 * time.Second

	// MDIO pins:
	pinMDIO = machine.GPIO0
	pinMDC  = machine.GPIO1
	// Reference clock: (50MHz from PHY)
	// Mistakenly spelled as Retclk on breakout.
	pinRefClk = machine.GPIO2
	// RX pins: GPIO 3, 4, 5 (RXD0, RXD1, CRS_DV)
	pinRxBase = machine.GPIO3
	// TX pins: GPIO 7, 8, 9 (TXD0, TXD1, TX_EN)
	pinTxBase = machine.GPIO7
)

const (
	actionMarker = "<!--A-->"
	ntpHost      = "192.168.1.100" //"pool.ntp.org"
)

var (

	//go:embed template.html
	htmlTemplate  []byte
	htmlActionIdx = bytes.Index(htmlTemplate, []byte(actionMarker)) + len(actionMarker)
	requestedIP   = [4]byte{192, 168, 1, 99}
)

func main() {
	time.Sleep(1 * time.Second)
	println("starting HTTP server example")
	logger := slog.New(slog.NewTextHandler(machine.Serial, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Configure LED.
	machine.LED.Configure(machine.PinConfig{Mode: machine.PinOutput})

	baud := 1e6 * linkmode.SpeedMbps()
	dev, err := lan8720.NewPicoLAN8720Single(lan8720.PicoConfig{
		PHYConfig: lan8720.Config{
			PHYAddr:       1,
			Advertisement: phy.NewANAR().With100M(),
		},
		PIO:  pio.PIO0,
		MDC:  pinMDC,
		MDIO: pinMDIO,
		TxConfig: piolib.RMIITxConfig{
			Baud:     uint32(baud),
			TxBuffer: make([]byte, lannet.MFU),
			TxBase:   pinTxBase,
			RefClk:   pinRefClk,
		},
		RxConfig: piolib.RMIIRxConfig{
			Baud:           uint32(baud),
			RxBase:         pinRxBase,
			IRQ:            0,
			IRQSourceIndex: 0,
		},
	})
	if err != nil {
		panic("lan8720 config: " + err.Error())
	}
	link, err := dev.WaitAutoNegotiation(5 * time.Second)
	if err != nil {
		panic("waiting for auto neg: " + err.Error())
	}
	logger.Info("link established", slog.String("link", link.String()))

	mac := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	stack, err := lannet.NewStack(dev, mac, lannet.StackConfig{
		Hostname:          "http-pico",
		MaxActiveTCPPorts: 1,
		Logger:            logger,
		EnableRxPcapPrint: true,
		EnableTxPcapPrint: true,
		ICMPQueueLimit:    icmpQueue,
	})
	if err != nil {
		panic("stack config: " + err.Error())
	}

	go loopForeverStack(stack)

	const (
		dhcpTimeout = 7000 * time.Millisecond
		dhcpRetries = 3
		pollTime    = 5 * time.Millisecond
	)
	llstack := stack.LnetoStack()
	rstack := llstack.StackRetrying(backoff)
	results, err := rstack.DoDHCPv4(requestedIP, dhcpTimeout, dhcpRetries)
	if err != nil {
		panic("DHCP failed: " + err.Error())
	}
	err = llstack.AssimilateDHCPResults(results)
	if err != nil {
		panic("DHCP result assimilate failed: " + err.Error())
	}
	gatewayHW, err := rstack.DoResolveHardwareAddress6(results.Router, 500*time.Millisecond, 4)
	if err != nil {
		panic("ARP resolve failed: " + err.Error())
	}
	llstack.SetGatewayHardwareAddr(gatewayHW)
	llstack.Debug("post-dhcp")
	logger.Info("DHCP complete",
		slog.String("ourIP", string(ipv4.AppendFormatAddr(nil, results.AssignedAddr4))),
		slog.String("router", results.Router.String()),
		slog.String("gatewayhw", net.HardwareAddr(gatewayHW[:]).String()),
	)

	// DNS lookup for NTP server.
	ntpaddr, err := netip.ParseAddr(ntpHost)
	if err != nil {
		logger.Info("resolving NTP host", slog.String("host", ntpHost))
		addrs, err := rstack.DoLookupIP(ntpHost, 5*time.Second, 3)
		if err != nil {
			panic("DNS lookup failed: " + err.Error())
		}
		ntpaddr = addrs[0]
	}
	logger.Info("DNS resolved", slog.String("addr", ntpaddr.String()))

	// Perform NTP request.
	logger.Info("starting NTP request")
	offset, err := rstack.DoNTP(ntpaddr, 5*time.Second, 3)
	if err != nil {
		panic("NTP failed: " + err.Error())
	}
	now := time.Now().Add(offset)
	logger.Info("NTP complete",
		slog.String("time", now.String()),
		slog.Duration("offset", offset),
	)
	runtime.AdjustTimeOffset(int64(offset))

	tcpPool, err := xnet.NewTCPPool(xnet.TCPPoolConfig{
		PoolSize:           maxConns,
		QueueSize:          3,
		TxBufSize:          len(htmlTemplate) + 1024,
		RxBufSize:          1024,
		EstablishedTimeout: 5 * time.Second,
		ClosingTimeout:     5 * time.Second,
		NewBackoff:         func() lneto.BackoffStrategy { return backoff },
	})
	if err != nil {
		panic("tcppool create: " + err.Error())
	}
	if icmpQueue > 0 {
		println("enable ICMP")
		err = llstack.EnableICMP(true)
		if err != nil {
			println("error enabling icmp:", err.Error())
		}
	}
	listenAddr := netip.AddrPortFrom(netip.AddrFrom4(results.AssignedAddr4), listenPort)

	var listener tcp.Listener
	err = listener.Reset(listenPort, tcpPool)
	if err != nil {
		panic("listener reset: " + err.Error())
	}
	err = llstack.RegisterListenerTCP(&listener)
	if err != nil {
		panic("listener register: " + err.Error())
	}

	// server outlives main's frame via the mux, so it is heap allocated once here
	// rather than living as a package-level global.
	server := &Server{}
	var mux httphi.MuxSlice
	mux.Reset(2)
	mux.Handle("GET /", server.HandleLanding)
	mux.Handle("GET /toggle-led", server.HandleToggleLED)

	var router httphi.Router
	err = router.Configure(httphi.RouterConfig{
		// Fixed worker mode: goroutines and exchange buffers are allocated here
		// and never again, so serving load costs no heap.
		FixedNumGoroutines:          maxConns,
		RequestHeaderBufferSize:     reqHdrBuf,
		ResponseHeaderMinBufferSize: respHdrBuf,
		RequestNumHeaderKVCap:       16,
		Mux:                         &mux,
		Logger:                      logger,
	})
	if err != nil {
		panic("router configure: " + err.Error())
	}

	logger.Info("listening", slog.String("addr", "http://"+listenAddr.String()))
	llstack.Debug("init-complete")

	for {
		if listener.NumberOfReadyToAccept() == 0 {
			time.Sleep(loopSleep)
			tcpPool.CheckTimeouts()
			continue
		}
		conn, _, err := listener.TryAccept()
		if err != nil {
			logger.Error("listener accept:", slog.String("err", err.Error())) // TODO(HEAP): real slog allocates 121B/11 mallocs
			time.Sleep(time.Second)
			continue
		}
		remoteAddr, _ := netip.AddrFromSlice(conn.RemoteAddr())
		print("incoming connection: ")
		printAddr(remoteAddr)
		println(" from port", conn.RemotePort())

		// The router's read loop backs off indefinitely on a silent peer, the
		// deadline is what bounds the exchange.
		conn.SetDeadline(time.Now().Add(connTimeout))
		err = router.Handle(conn)
		if err != nil {
			// Router refused the connection (no free exchange or full queue): it
			// left conn untouched, so disposing of it is ours to do.
			stack.DebugErr("router failed to handle", err.Error())
			conn.Close()
		}
	}
}

// Server owns everything the HTTP handlers touch: the LED action log and the
// scratch memory they build responses in. One instance lives for the program's
// life, so its handlers are method values registered once on the mux.
type Server struct {
	state     ServerState
	scratches [maxConns]scratch
}

// acquireScratch claims a free scratch buffer, or nil if every one is in use. Sized to
// maxConns, one per router worker, so it never fails in practice.
func (sv *Server) acquireScratch() *scratch {
	for i := range sv.scratches {
		if sv.scratches[i].inUse.CompareAndSwap(false, true) {
			return &sv.scratches[i]
		}
	}
	return nil
}

func (sv *Server) HandleLanding(ex *httphi.Exchange) {
	sc := sv.acquireScratch()
	if sc == nil {
		ex.WriteHeader(httphi.StatusServiceUnavailable)
		return
	}
	defer sc.release()
	println("Got webpage request!")

	dynContent := sv.state.AppendActionsHTML(sc.dyn[:0])
	ex.StageStatus(int(httphi.StatusOK))
	ex.StageHeader("Content-Type", "text/html")
	ex.StageHeaderInt("Content-Length", int64(len(htmlTemplate)+len(dynContent)))
	// We close the connection on exchange end. Omitting Connection:close means
	// notably slower paint times in the browser, and it needs the Content-Length
	// above to know the body ended.
	ex.StageHeader("Connection", "close")
	ex.WriteBody(htmlTemplate[:htmlActionIdx])
	ex.WriteBody(dynContent)
	ex.WriteBody(htmlTemplate[htmlActionIdx:])
}

func (sv *Server) HandleToggleLED(ex *httphi.Exchange) {
	println("got toggle led request")
	// AppendQuery decodes percent escapes and '+' for us; sc.cs is sized so the
	// decode never needs to grow the slice onto the heap.
	rawCallsign, _ := ex.RequestQueryValue("callsign")
	sv.state.RecordToggle(trimSanitized(rawCallsign))
	ex.Respond(200, "", nil)
}

// scratch is per-in-flight-request working memory for handlers. The router's
// exchange buffer cannot serve as scratch: staged response headers are written
// into it, and the landing page needs its dynamic section fully built to know
// the Content-Length to stage.
//
// Claim one with [Server.acquire].
type scratch struct {
	inUse atomic.Bool
	dyn   [768]byte // Dynamic HTML section of the landing page.
	cs    [192]byte // Decoded callsign query parameter.
}

func (sc *scratch) release() { sc.inUse.Store(false) }

// ServerState stores the state of the HTTP server. It has a ring buffer with last 8 actions
// performed. Every time a new action is performed it replaces the oldest action by advancing the ring buffer.
type ServerState struct {
	mu            sync.Mutex
	ActionRingBuf [16]Action
	LastAction    int
	LEDState      bool
}

type Action struct {
	Time        time.Time
	Callsign    [9]byte // fits max "(unknown)".
	CallsignLen uint8
	TurnedLEDOn bool
}

func (s *ServerState) RecordToggle(callsign []byte) {
	if len(callsign) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LEDState = !s.LEDState
	machine.LED.Set(s.LEDState)
	idx := s.LastAction % len(s.ActionRingBuf)
	a := &s.ActionRingBuf[idx]
	a.Time = time.Now()
	a.TurnedLEDOn = s.LEDState
	n := copy(a.Callsign[:], callsign)
	a.CallsignLen = uint8(n)
	s.LastAction++
}

func (s *ServerState) AppendActionsHTML(buf []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := s.LastAction
	if count > len(s.ActionRingBuf) {
		count = len(s.ActionRingBuf)
	}
	if count == 0 {
		return buf
	}
	now := time.Now()
	buf = append(buf, "<ul>"...)
	for i := 0; i < count; i++ {
		idx := (s.LastAction - 1 - i) % len(s.ActionRingBuf)
		a := &s.ActionRingBuf[idx]
		buf = append(buf, "<li>"...)
		buf = append(buf, a.Callsign[:a.CallsignLen]...)
		if a.TurnedLEDOn {
			buf = append(buf, " turned led on "...)
		} else {
			buf = append(buf, " turned led off "...)
		}
		buf = appendDurationAgo(buf, now.Sub(a.Time))
		buf = append(buf, "</li>"...)
	}
	buf = append(buf, "</ul>"...)
	return buf
}

func appendDurationAgo(dst []byte, d time.Duration) []byte {
	var val int64
	var unit byte
	sec := int64(d / time.Second)
	switch {
	case sec < 60:
		val, unit = sec, 's'
	case sec < 3600:
		val, unit = sec/60, 'm'
	case sec < 86400:
		val, unit = sec/3600, 'h'
	default:
		val, unit = sec/86400, 'd'
	}
	dst = strconv.AppendInt(dst, val, 10)
	dst = append(dst, unit)
	dst = append(dst, " ago "...)
	return dst
}

func trimSanitized(raw []byte) []byte {
	for i, b := range raw {
		isAlpha := (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
		if i >= 4 || (!isAlpha && b != '.' && b != '_') {
			return raw[:i]
		}
	}
	return raw
}

// printAddr prints a netip.Addr without heap allocation by formatting into a
// stack buffer.
func printAddr(addr netip.Addr) {
	var buf [48]byte
	b := addr.AppendTo(buf[:0])
	print(unsafe.String(&b[0], len(b)))
}

func loopForeverStack(stack *lannet.Stack) {
	for {
		send, recv, _ := stack.RecvAndSend()
		if send == 0 && recv == 0 {
			time.Sleep(loopSleep)
		}
	}
}

func backoff(consecutiveBackoffs uint) time.Duration {
	return min(3*time.Second, 1<<min(consecutiveBackoffs, 31))
}
