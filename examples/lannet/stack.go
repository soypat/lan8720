//go:build rp2040 || rp2350

package lannet

import (
	"context"
	"hash/crc32"
	"log/slog"
	"machine"
	"net/netip"
	"time"

	"github.com/soypat/lan8720"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/x/xnet"
)

const (
	MTU = 1500
	MFU = MTU + ethernet.MaxOverheadSize
)

// Stack wraps the LAN8720 device with lneto's networking stack.
type Stack struct {
	s       xnet.StackAsync
	dev     *lan8720.DeviceSingle
	log     *slog.Logger
	sendbuf []byte
	rxbuf   []byte
	rxgot   int
	// pcap fields for packet capture printing.
	pcap         xnet.CapturePrinter
	enableRxPcap bool
	enableTxPcap bool
}

type StackConfig struct {
	StaticAddress     netip.Addr
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
	if cfg.EnableRxPcapPrint || cfg.EnableTxPcapPrint {
		stack.pcap.Configure(serialWriter{}, xnet.CapturePrinterConfig{
			TimePrecision: 3,
			Now:           time.Now,
		})
	}

	// Configure networking stack.
	err := stack.s.Reset(xnet.StackConfig{
		StaticAddress:   cfg.StaticAddress,
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
		if err != nil {
			stack.logerr("RecvAndSend:Demux", slog.Int("plen", n), slog.String("err", err.Error()))
		}
		// Immediately start another receive.
		rxerr := dev.StartRxSingle()
		if rxerr != nil {
			stack.logerr("RecvAndSend:StartRxSingle", slog.String("err", rxerr.Error()))
		}
	}

	// Check if there's data to send.
	send, err = stack.s.Encapsulate(stack.sendbuf, -1, 0)
	if err != nil {
		stack.logerr("RecvAndSend:Encapsulate", slog.Int("plen", send), slog.String("err", err.Error()))
		return send, recv, err
	}
	if send == 0 {
		return send, recv, nil
	}

	if stack.enableTxPcap {
		stack.printPcap("TX", stack.sendbuf[:send])
	}

	// Send the packet.
	err = dev.SendFrame(stack.sendbuf[:send])
	if err != nil {
		stack.logerr("RecvAndSend:SendFrame", slog.Int("plen", send), slog.String("err", err.Error()))
	}
	return send, recv, err
}

func (stack *Stack) printPcap(direction string, data []byte) {
	stack.pcap.PrintPacket(direction, data)
}

func (stack *Stack) logerr(msg string, attrs ...slog.Attr) {
	if stack.log != nil {
		stack.log.LogAttrs(context.Background(), slog.LevelError, msg, attrs...)
	}
}

type serialWriter struct{}

func (serialWriter) Write(b []byte) (int, error) {
	const chunkSize = 256
	const sleep = 30 * time.Millisecond
	total := len(b)
	for len(b) > 0 {
		n := min(len(b), chunkSize)
		machine.Serial.Write(b[:n])
		b = b[n:]
		if len(b) > 0 {
			time.Sleep(sleep)
		}
	}
	return total, nil
}
