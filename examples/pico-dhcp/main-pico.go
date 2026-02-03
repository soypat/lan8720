//go:build rp2040 || rp2350

package main

// WARNING: default -scheduler=cores unsupported, compile with -scheduler=tasks set!

import (
	"log/slog"
	"machine"
	"net"
	"time"

	"github.com/soypat/lan8720"
	"github.com/soypat/lan8720/examples/lannet"
	"github.com/soypat/lneto/phy"
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
)

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
	link, err := dev.WaitAutoNegotiation(2 * time.Second)
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
		timeout  = 100 * time.Millisecond
		retries  = 100
		pollTime = 5 * time.Millisecond
	)
	llstack := stack.LnetoStack()
	rstack := llstack.StackRetrying(pollTime)
	results, err := rstack.DoDHCPv4(requestedIP, timeout, retries)
	if err != nil {
		panic("DHCP failed: " + err.Error())
	}
	gatewayHW, err := rstack.DoResolveHardwareAddress6(results.Router, 500*time.Millisecond, 4)
	if err != nil {
		panic("ARP resolve failed: " + err.Error())
	}
	llstack.SetGateway6(gatewayHW)
	logger.Info("DHCP complete",
		slog.String("hostname", stack.Hostname()),
		slog.String("ourIP", results.AssignedAddr.String()),
		slog.String("subnet", results.Subnet.String()),
		slog.String("router", results.Router.String()),
		slog.String("server", results.ServerAddr.String()),
		slog.String("broadcast", results.BroadcastAddr.String()),
		slog.String("gateway", results.Gateway.String()),
		slog.String("gatewayhw", net.HardwareAddr(gatewayHW[:]).String()),
		slog.Uint64("lease[seconds]", uint64(results.TLease)),
		slog.Uint64("rebind[seconds]", uint64(results.TRebind)),
		slog.Uint64("renew[seconds]", uint64(results.TRenewal)),
		slog.Any("DNS-servers", results.DNSServers),
	)

	// Keep the program running.
	for {
		time.Sleep(time.Second)
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
