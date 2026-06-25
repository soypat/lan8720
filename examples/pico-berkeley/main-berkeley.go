//go:build rp2040 || rp2350

package main

// WARNING: default -scheduler=cores unsupported, compile with -scheduler=tasks set!

import (
	"context"
	"log/slog"
	"machine"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/soypat/lan8720"
	"github.com/soypat/lan8720/examples/lannet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/phy"
	"github.com/soypat/lneto/x/xnet"
	pio "github.com/tinygo-org/pio/rp2-pio"
	"github.com/tinygo-org/pio/rp2-pio/piolib"
)

// Pin configuration matching reference implementation.
const (
	linkmode = phy.Link100FDX
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
	requestedIP = [4]byte{192, 168, 1, 99}
	nanotime    = func() int64 {
		return time.Now().UnixNano()
	}
)

const httpBuf = 1024

type connState struct {
	hdr     httpraw.Header
	httpBuf [httpBuf]byte
}

func main() {
	time.Sleep(1 * time.Second) // Give time to connect to USB and monitor output.
	println("starting program")
	logger := slog.New(slog.NewTextHandler(machine.Serial, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	baud := 1e6 * linkmode.SpeedMbps()
	dev, err := lan8720.NewPicoLAN8720Single(lan8720.PicoConfig{
		PHYConfig: lan8720.Config{
			PHYAddr:       1, // By default PHY addr is 1.
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

	// Get hardware address from PHY (use PHY address as part of MAC).
	// LAN8720 doesn't have a built-in MAC, so we generate one.
	mac := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01} // Locally administered MAC

	// Create networking stack.
	stack, err := lannet.NewStack(dev, mac, lannet.StackConfig{
		Hostname:          "pico-eth",
		MaxActiveTCPPorts: 4,
		Logger:            logger,
		EnableRxPcapPrint: true,
		EnableTxPcapPrint: true,
	})
	if err != nil {
		panic("stack config: " + err.Error())
	}

	// Start goroutine to process network packets.
	go loopForeverStack(stack)

	const (
		timeout  = 7000 * time.Millisecond
		retries  = 3
		pollTime = 5 * time.Millisecond
	)
	llstack := stack.LnetoStack()
	rstack := llstack.StackRetrying(backoff)
	results, err := rstack.DoDHCPv4(requestedIP, timeout, retries)
	if err != nil {
		panic("DHCP failed: " + err.Error())
	}
	err = llstack.AssimilateDHCPResults(results)
	if err != nil {
		panic("DHCP result assimilate failed: " + err.Error())
	}
	println("DHCP done. Addr:", string(ipv4.AppendFormatAddr(nil, results.AssignedAddr4)))
	gatewayHW, err := rstack.DoResolveHardwareAddress6(results.Router, 500*time.Millisecond, 4)
	if err != nil {
		panic("ARP resolve failed: " + err.Error())
	}
	llstack.SetGatewayHardwareAddr(gatewayHW)

	berkstack := llstack.StackGo(backoff, xnet.StackGoConfig{
		ListenerPoolConfig: xnet.TCPPoolConfig{
			PoolSize:           4, // 4 max connections
			QueueSize:          4,
			TxBufSize:          2048,
			RxBufSize:          2048,
			EstablishedTimeout: 4 * time.Second,
			ClosingTimeout:     2 * time.Second,
			NanoTime:           nanotime,
		},
	})
	// passive TCP listen, raddr is nil.
	// raddr := &net.TCPAddr{
	// 	IP:   []byte{192, 168, 1, 53},
	// 	Port: 80,
	// }
	laddr := netip.AddrPortFrom(netip.AddrFrom4(results.AssignedAddr4), 80)
	laddrString := laddr.String()
	println("prepare to listen on socket", laddrString)

	const sockstream = 0x1
	iconn, err := berkstack.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockstream, laddr, netip.AddrPort{})
	if err != nil {
		println("socket err:", err.Error())
		panic("failed on socket listen")
	}

	listener := iconn.(net.Listener)
	var buf [1024]byte
	for {
		time.Sleep(pollTime)
		conn, err := listener.Accept()
		if err != nil {
			println("accept error:", err.Error())
			continue
		}
		n, err := conn.Read(buf[:])
		if err != nil {
			println("read error:", err.Error())
		}
		if n > 0 {
			conn.Write(buf[:n])
		}
		time.Sleep(50 * time.Millisecond)
		conn.Close()
		time.Sleep(50 * time.Millisecond)
		println("close conn")
	}
}

func loopForeverStack(stack *lannet.Stack) {
	for {
		send, recv, _ := stack.RecvAndSend()
		if send == 0 && recv == 0 {
			time.Sleep(5 * time.Millisecond) // No data to send or receive, sleep for a bit.
		}
	}
}

func backoff(consecutiveBackoffs uint) time.Duration {
	return min(3*time.Second, 1<<min(consecutiveBackoffs, 31))
}
