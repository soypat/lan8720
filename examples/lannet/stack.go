//go:build rp2040 || rp2350

package lannet

import (
	"hash/crc32"
	"log/slog"
	"machine"
	"time"

	"github.com/soypat/lan8720"
	"github.com/soypat/lneto"
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
	StaticAddress4    [4]byte
	Hostname          string
	MaxActiveTCPPorts uint16
	MaxActiveUDPPorts uint16
	ICMPQueueLimit    int
	AcceptMulticast   bool
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
		StaticAddress4:    cfg.StaticAddress4,
		Hostname:          cfg.Hostname,
		MaxActiveTCPPorts: cfg.MaxActiveTCPPorts,
		MaxActiveUDPPorts: cfg.MaxActiveUDPPorts,
		AcceptMulticast:   cfg.AcceptMulticast,
		RandSeed:          time.Now().UnixNano() ^ int64(cfg.RandSeed),
		HardwareAddress:   mac,
		MTU:               MTU,
		EthernetTxCRC32Update: func(crc uint32, b []byte) uint32 {
			return crc32.Update(crc, crcTable, b)
		},
		ICMPQueueLimit: cfg.ICMPQueueLimit,
		// Logger:         cfg.Logger,
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

// Debug forwards to the underlying StackAsync for allocation/debug instrumentation.
func (stack *Stack) Debug(msg string) { stack.s.Debug(msg) }

// DebugErr forwards to the underlying StackAsync for allocation/debug instrumentation.
func (stack *Stack) DebugErr(msg, err string) { stack.s.DebugErr(msg, err) }

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
		// HEAP: markers bracketing the demux error path. Each demux error costs a
		// deterministic 209B/19 mallocs; these localise it. The baseline marker must
		// stay silent on the normal path, so any output from it is itself a finding.
		logAllocs("rx:pre-ingress")
		err = stack.s.IngressEthernet(stack.rxbuf[:n])
		logAllocs("rx:post-ingress")
		if err != nil {
			if err != lneto.ErrPacketDrop {
				errstr := err.Error()
				logAllocs("rx:post-errstring")
				stack.logerr("demux", errstr)
			} else {
				println("packet drop")
			}
		}
		// Immediately start another receive.
		rxerr := dev.StartRxSingle()
		if rxerr != nil {
			stack.logerr("RecvAndSend:StartRxSingle", rxerr.Error())
		}
	}

	// Check if there's data to send.
	send, err = stack.s.EgressEthernet(stack.sendbuf)
	if err != nil {
		stack.logerr("encaps", err.Error())
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
		stack.logerr("sendframe", err.Error())
	}
	return send, recv, err
}

func (stack *Stack) printPcap(direction string, data []byte) {
	stack.pcap.PrintEthernet(direction, data)
}

func (stack *Stack) logerr(msg string, err string, attrs ...slog.Attr) {
	// Forward unconditionally: DebugErr runs the heap allocation probe before it
	// gates on the logger, so skipping it here would also skip the measurement.
	stack.Debug("rx:pre-debugerr")
	stack.s.DebugErr(msg, err)
}

type serialWriter struct{}

func (serialWriter) Write(b []byte) (int, error) {
	return machine.Serial.Write(b)
}

func logAllocs(msg string) {
	xnet.LogAllocs(msg)
}
