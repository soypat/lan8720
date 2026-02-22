//go:build rp2040 || rp2350

package main

// WARNING: default -scheduler=cores unsupported, compile with -scheduler=tasks set!

import (
	"log/slog"
	"machine"
	"net"
	"net/netip"
	"strconv"
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
	maxConns   = 3
	httpBuf    = 512

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

var (
	//go:embed index.html
	webPage []byte

	requestedIP = [4]byte{192, 168, 1, 99}

	lastLedState bool
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
	logger.Info("DHCP complete",
		slog.String("ourIP", results.AssignedAddr.String()),
		slog.String("router", results.Router.String()),
		slog.String("gatewayhw", net.HardwareAddr(gatewayHW[:]).String()),
	)

	tcpPool, err := xnet.NewTCPPool(xnet.TCPPoolConfig{
		PoolSize:           maxConns,
		QueueSize:          3,
		TxBufSize:          len(webPage) + 128,
		RxBufSize:          1024,
		EstablishedTimeout: 5 * time.Second,
		ClosingTimeout:     5 * time.Second,
		NewUserData: func() any {
			var hdr httpraw.Header
			buf := make([]byte, httpBuf)
			hdr.Reset(buf)
			return &hdr
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

	for {
		if listener.NumberOfReadyToAccept() == 0 {
			time.Sleep(loopSleep)
			tcpPool.CheckTimeouts()
			continue
		}

		conn, httpBuf, err := listener.TryAccept()
		if err != nil {
			logger.Error("listener accept:", slog.String("err", err.Error()))
			time.Sleep(time.Second)
			continue
		}
		go handleConn(conn, httpBuf.(*httpraw.Header))
	}
}

type page uint8

const (
	pageNotExists page = iota
	pageLanding
	pageToggleLED
)

func handleConn(conn *tcp.Conn, hdr *httpraw.Header) {
	defer conn.Close()
	const AsRequest = false
	var buf [64]byte
	hdr.Reset(nil)

	remoteAddr, _ := netip.AddrFromSlice(conn.RemoteAddr())
	println("incoming connection:", remoteAddr.String(), "from port", conn.RemotePort())

	for {
		n, err := conn.Read(buf[:])
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
		closed := err == net.ErrClosed || conn.State() != tcp.StateEstablished
		if closed {
			break
		} else if hdr.BufferReceived() >= httpBuf {
			println("too much HTTP data")
			return
		}
	}

	var requestedPage page
	uri := hdr.RequestURI()
	switch string(uri) {
	case "/":
		println("Got webpage request!")
		requestedPage = pageLanding
	case "/toggle-led":
		println("got toggle led request")
		requestedPage = pageToggleLED
		lastLedState = !lastLedState
		machine.LED.Set(lastLedState)
	}

	hdr.Reset(nil)
	hdr.SetProtocol("HTTP/1.1")
	if requestedPage == pageNotExists {
		hdr.SetStatus("404", "Not Found")
	} else {
		hdr.SetStatus("200", "OK")
	}
	var body []byte
	switch requestedPage {
	case pageLanding:
		body = webPage
		hdr.Set("Content-Type", "text/html")
	}
	if len(body) > 0 {
		hdr.Set("Content-Length", strconv.Itoa(len(body)))
	}
	responseHeader, err := hdr.AppendResponse(buf[:0])
	if err != nil {
		println("error appending:", err.Error())
	}
	conn.Write(responseHeader)
	if len(body) > 0 {
		_, err := conn.Write(body)
		if err != nil {
			println("writing body:", err.Error())
		}
		time.Sleep(loopSleep)
	}
}

func loopForeverStack(stack *lannet.Stack) {
	for {
		send, recv, _ := stack.RecvAndSend()
		if send == 0 && recv == 0 {
			time.Sleep(loopSleep)
		}
	}
}
