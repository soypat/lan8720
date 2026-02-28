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
	"time"

	_ "embed"

	"github.com/soypat/lan8720"
	"github.com/soypat/lan8720/examples/lannet"
	"github.com/soypat/lneto/http/httpraw"
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
	maxConns   = 10
	httpBuf    = 1024

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
	ntpHost      = "pool.ntp.org"
)

var (

	//go:embed template.html
	htmlTemplate  []byte
	htmlActionIdx = bytes.Index(htmlTemplate, []byte(actionMarker)) + len(actionMarker)
	requestedIP   = [4]byte{192, 168, 1, 99}
)

func main() {
	time.Sleep(2 * time.Second)
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
		MaxTCPPorts:       1,
		Logger:            logger,
		EnableRxPcapPrint: true,
		EnableTxPcapPrint: true,
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
	rstack := llstack.StackRetrying(pollTime)
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
	llstack.SetGateway6(gatewayHW)
	llstack.Debug("post-dhcp")
	logger.Info("DHCP complete",
		slog.String("ourIP", results.AssignedAddr.String()),
		slog.String("router", results.Router.String()),
		slog.String("gatewayhw", net.HardwareAddr(gatewayHW[:]).String()),
	)

	// DNS lookup for NTP server.
	logger.Info("resolving NTP host", slog.String("host", ntpHost))
	addrs, err := rstack.DoLookupIP(ntpHost, 5*time.Second, 3)
	if err != nil {
		panic("DNS lookup failed: " + err.Error())
	}
	logger.Info("DNS resolved", slog.String("addr", addrs[0].String()))

	// Perform NTP request.
	logger.Info("starting NTP request")
	offset, err := rstack.DoNTP(addrs[0], 5*time.Second, 3)
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
		NewUserData: func() any {
			cs := new(connState)
			cs.hdr.Reset(cs.httpBuf[:])
			return cs
		},
	})
	if err != nil {
		panic("tcppool create: " + err.Error())
	}

	listenAddr := netip.AddrPortFrom(results.AssignedAddr, listenPort)

	var listener tcp.Listener
	err = listener.Reset(listenPort, tcpPool)
	if err != nil {
		panic("listener reset: " + err.Error())
	}
	err = llstack.RegisterListener(&listener)
	if err != nil {
		panic("listener register: " + err.Error())
	}

	logger.Info("listening", slog.String("addr", "http://"+listenAddr.String()))
	llstack.Debug("init-complete")

	// Pre-allocate worker goroutines so stacks are allocated once at startup
	// instead of per-connection. Maintains full concurrency up to maxConns.
	jobCh := make(chan connJob, maxConns)
	for range maxConns {
		go connWorker(jobCh)
	}

	for {
		if listener.NumberOfReadyToAccept() == 0 {
			time.Sleep(loopSleep)
			tcpPool.CheckTimeouts()
			continue
		}

		conn, userData, err := listener.TryAccept()
		if err != nil {
			logger.Error("listener accept:", slog.String("err", err.Error())) // TODO(HEAP): real slog allocates 121B/11 mallocs
			time.Sleep(time.Second)
			continue
		}
		jobCh <- connJob{conn: conn, cs: userData.(*connState), stack: llstack}
	}
}

// connState holds all per-connection buffers, pre-allocated during pool init.
// Eliminates per-connection heap escapes of local arrays (buf, dynBuf, csBuf)
// and the make([]byte, httpBuf) that exceeds TinyGo's 256-byte stack limit.
type connState struct {
	hdr     httpraw.Header
	httpBuf [httpBuf]byte
	buf     [128]byte
	dynBuf  [256]byte
	csBuf   [9]byte
}

type connJob struct {
	conn  *tcp.Conn
	cs    *connState
	stack *xnet.StackAsync
}

type page uint8

const (
	pageNotExists page = iota
	pageLanding
	pageToggleLED
)

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

var state ServerState

func (s *ServerState) RecordToggle(callsign []byte) {
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

func parseCallsignValue(query []byte) []byte {
	const key = "callsign="
	idx := bytes.Index(query, []byte(key))
	if idx < 0 || (idx > 0 && query[idx-1] != '&') {
		return nil
	}
	val := query[idx+len(key):]
	if end := bytes.IndexByte(val, '&'); end >= 0 {
		val = val[:end]
	}
	return val
}

func sanitizeCallsign(dst, raw []byte) []byte {
	dst = dst[:0]
	for _, b := range raw {
		if (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') {
			break
		}
		dst = append(dst, b)
		if len(dst) >= 4 {
			break
		}
	}
	if len(dst) == 0 {
		dst = append(dst, "(unknown)"...)
	}
	return dst
}

func connWorker(ch <-chan connJob) {
	for job := range ch {
		handleConn(job.conn, job.cs, job.stack)
	}
}

func handleConn(conn *tcp.Conn, cs *connState, stack *xnet.StackAsync) {
	defer conn.Close()
	const AsRequest = false
	hdr := &cs.hdr
	hdr.Reset(nil)
	buf := cs.buf[:]

	stack.Debug("conn-start")
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	remoteAddr, _ := netip.AddrFromSlice(conn.RemoteAddr())
	println("incoming connection:", remoteAddr.String(), "from port", conn.RemotePort())
	stack.Debug("post-deadline+println")

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			hdr.ReadFromBytes(buf[:n])
			needMoreData, err := hdr.TryParse(AsRequest)
			if err != nil && !needMoreData {
				println("parsing HTTP request:", err.Error())
				return
			}
			if !needMoreData {
				break
			}
		}
		if err != nil {
			println("read error:", err.Error())
			return
		}
		closed := conn.State() != tcp.StateEstablished
		if closed {
			break
		} else if hdr.BufferReceived() >= httpBuf {
			println("too much HTTP data")
			return
		}
	}

	uri := hdr.RequestURI()
	uriPath := uri
	var uriQuery []byte
	if qIdx := bytes.IndexByte(uri, '?'); qIdx >= 0 {
		uriPath = uri[:qIdx]
		uriQuery = uri[qIdx+1:]
	}

	var requestedPage page
	switch string(uriPath) {
	case "/":
		println("Got webpage request!")
		requestedPage = pageLanding
	case "/toggle-led":
		println("got toggle led request")
		requestedPage = pageToggleLED
		callsign := sanitizeCallsign(cs.csBuf[:0], parseCallsignValue(uriQuery))
		state.RecordToggle(callsign)
	}

	stack.Debug("post-read-loop")
	// Reuse header to write response.
	hdr.Reset(nil)
	hdr.SetProtocol("HTTP/1.1")
	if requestedPage == pageNotExists {
		hdr.SetStatus("404", "Not Found")
	} else {
		hdr.SetStatus("200", "OK")
	}

	stack.Debug("pre-response")
	switch requestedPage {
	case pageLanding:
		dynContent := state.AppendActionsHTML(cs.dynBuf[:0])
		hdr.Set("Content-Type", "text/html")
		hdr.Set("Content-Length", strconv.Itoa(len(htmlTemplate)+len(dynContent)))
		responseHeader, err := hdr.AppendResponse(buf[:0])
		if err != nil {
			println("error appending:", err.Error())
		}
		conn.Write(responseHeader)
		conn.Write(htmlTemplate[:htmlActionIdx])
		conn.Write(dynContent)
		conn.Write(htmlTemplate[htmlActionIdx:])
		time.Sleep(loopSleep)

	case pageToggleLED:
		hdr.Set("Content-Length", "0")
		responseHeader, err := hdr.AppendResponse(buf[:0])
		if err != nil {
			println("error appending:", err.Error())
		}
		conn.Write(responseHeader)

	default:
		responseHeader, err := hdr.AppendResponse(buf[:0])
		if err != nil {
			println("error appending:", err.Error())
		}
		conn.Write(responseHeader)
	}
	stack.Debug("pre-close")
}

func loopForeverStack(stack *lannet.Stack) {
	for {
		send, recv, _ := stack.RecvAndSend()
		if send == 0 && recv == 0 {
			time.Sleep(loopSleep)
		}
	}
}
