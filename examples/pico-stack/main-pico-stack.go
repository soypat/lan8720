//go:build rp2040 || rp2350

package main

// WARNING: default -scheduler=cores unsupported, compile with -scheduler=tasks set!

import (
	"hash/crc32"
	"log/slog"
	"machine"
	"net"
	"time"

	"github.com/soypat/lan8720"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/phy"
	"github.com/soypat/lneto/x/xnet"
	pio "github.com/tinygo-org/pio/rp2-pio"
	"github.com/tinygo-org/pio/rp2-pio/piolib"
)

// Pin configuration matching reference implementation.
const (
	MTU      = 1500
	MFU      = MTU + 14 + 4
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
	time.Sleep(2 * time.Second) // Give time to connect to USB and monitor output.
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
			TxBuffer: make([]byte, MFU),
			TxBase:   pinTxBase,
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
	stack, err := NewStack(dev, mac, StackConfig{
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
		timeout  = 6 * time.Second
		retries  = 3
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

func loopForeverStack(stack *Stack) {
	for {
		send, recv, _ := stack.RecvAndSend()
		if send == 0 && recv == 0 {
			time.Sleep(5 * time.Millisecond) // No data to send or receive, sleep for a bit.
		}
	}
}

// Stack wraps the LAN8720 device with lneto's networking stack.
type Stack struct {
	s       xnet.StackAsync
	dev     *lan8720.DeviceSingle
	log     *slog.Logger
	sendbuf []byte
	rxbuf   []byte
	rxgot   int
	// pcap fields for packet capture printing.
	pc           pcap.PacketBreakdown
	pcfmt        pcap.Formatter
	frms         []pcap.Frame
	printdata    []byte
	enableRxPcap bool
	enableTxPcap bool
}

type StackConfig struct {
	Hostname          string
	MaxTCPPorts       int
	RandSeed          int64
	Logger            *slog.Logger
	EnableRxPcapPrint bool
	EnableTxPcapPrint bool
}

// crcTable is the IEEE CRC-32 table used for Ethernet FCS calculation.
var crcTable = crc32.MakeTable(crc32.IEEE)

func NewStack(dev *lan8720.DeviceSingle, mac [6]byte, cfg StackConfig) (*Stack, error) {
	if cfg.Hostname == "" {
		cfg.Hostname = "pico-eth"
	}
	stack := &Stack{
		dev:          dev,
		log:          cfg.Logger,
		sendbuf:      make([]byte, MFU),
		rxbuf:        make([]byte, MFU),
		enableRxPcap: cfg.EnableRxPcapPrint,
		enableTxPcap: cfg.EnableTxPcapPrint,
	}

	// Configure networking stack.
	err := stack.s.Reset(xnet.StackConfig{
		Hostname:        cfg.Hostname,
		MaxTCPConns:     cfg.MaxTCPPorts,
		RandSeed:        time.Now().UnixNano() ^ int64(cfg.RandSeed),
		HardwareAddress: mac,
		MTU:             MTU,
		EthernetTxCRC32Update: func(crc uint32, b []byte) uint32 {
			return crc32.Update(crc, crcTable, b)
		},
	})
	if err != nil {
		return nil, err
	}

	// Set up receive handler that demuxes incoming packets.
	err = dev.SetRxHandler(stack.rxbuf[:], func(buf []byte) {
		stack.rxgot = len(buf)
	})
	if err != nil {
		return nil, err
	}

	// Start receiving.
	err = dev.StartRxSingle()
	if err != nil {
		return nil, err
	}

	return stack, nil
}

func (stack *Stack) Hostname() string {
	return stack.s.Hostname()
}

func (stack *Stack) Device() *lan8720.DeviceSingle {
	return stack.dev
}

func (stack *Stack) LnetoStack() *xnet.StackAsync {
	return &stack.s
}

func (stack *Stack) RecvAndSend() (send, recv int, err error) {
	dev := stack.dev

	// Process received packet if available.
	if stack.rxgot > 0 {
		n := stack.rxgot
		stack.rxgot = 0 // Reset before processing to avoid reprocessing.
		recv = n
		if stack.enableRxPcap {
			stack.printPcap("RX", stack.rxbuf[:n])
		}
		err = stack.s.Demux(stack.rxbuf[:n], 0)
		if err != nil && stack.log != nil {
			stack.log.Error("RecvAndSend:Demux", slog.Int("plen", n), slog.String("err", err.Error()))
		}
		// Immediately start another receive.
		rxerr := dev.StartRxSingle()
		if rxerr != nil && stack.log != nil {
			stack.log.Error("RecvAndSend:StartRxSingle", slog.String("err", rxerr.Error()))
		}
	}

	// Check if there's data to send.
	send, err = stack.s.Encapsulate(stack.sendbuf, -1, 0)
	if err != nil {
		if stack.log != nil {
			stack.log.Error("RecvAndSend:Encapsulate", slog.Int("plen", send), slog.String("err", err.Error()))
		}
		return send, recv, err
	}
	if send == 0 {
		return send, recv, nil
	}

	// Send the packet.
	err = dev.SendFrame(stack.sendbuf[:send])
	if err != nil && stack.log != nil {
		stack.log.Error("RecvAndSend:SendFrame", slog.Int("plen", send), slog.String("err", err.Error()))
	}
	if stack.enableTxPcap && err == nil {
		stack.printPcap("TX", stack.sendbuf[:send])
	}
	return send, recv, err
}

func (stack *Stack) printPcap(direction string, data []byte) {
	var perr error
	stack.printdata = append(stack.printdata[:0], direction...)
	stack.printdata = append(stack.printdata, ": "...)
	stack.frms, perr = stack.pc.CaptureEthernet(stack.frms[:0], data, 0)
	if perr != nil {
		println(direction, "pcap failed:", perr.Error())
		return
	}
	stack.printdata, perr = stack.pcfmt.FormatFrames(stack.printdata, stack.frms, data)
	if perr != nil {
		println(direction, "pcap format failed:", perr.Error())
		return
	}
	stack.printdata = append(stack.printdata, '\n')
	serialWrite(stack.printdata)
}

func serialWrite(b []byte) {
	const chunkSize = 256
	const sleep = 30 * time.Millisecond
	for len(b) > 0 {
		n := min(len(b), chunkSize)
		machine.Serial.Write(b[:n])
		b = b[n:]
		if len(b) > 0 {
			time.Sleep(sleep)
		}
	}
}
