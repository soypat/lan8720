package main

import (
	"encoding/binary"
	"machine"
	"time"

	"github.com/soypat/lan8720"
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internet/pcap"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv4/icmpv4"
	"github.com/soypat/lneto/phy"
	pio "github.com/tinygo-org/pio/rp2-pio"
	"github.com/tinygo-org/pio/rp2-pio/piolib"
)

// Pin configuration matching reference implementation.
// See makeEthernetMAC below to see how they are used.
const (
	MTU      = 1500
	MFU      = MTU + 14 + 4
	linkmode = phy.Link100FDX
	// MDIO pins:
	pinMDIO = machine.GPIO0
	pinMDC  = machine.GPIO1
	// Reference clock: 		 (50MHz from PHY)
	// Mistakenly spelled as Retclk on breakout.
	pinRefClk = machine.GPIO2

	// RX pins: GPIO 3, 4, 5 (RXD0, RXD1, CRS_DV)
	pinRxBase = machine.GPIO3

	// TX pins: GPIO 0, 1, 2 (TXD0, TXD1, TX_EN)
	pinTxBase = machine.GPIO7
)

func main() {
	baud := 1e6 * linkmode.SpeedMbps()
	linkmode.ANAR()
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
	println("link established: ", link.String())

	var txbuf, rxbuf, rxbufoffload [MFU]byte
	var rxgot int
	err = dev.SetRxHandler(rxbuf[:], func(buf []byte) {
		rxgot = len(buf)
	})
	if err != nil {
		panic("lan8720 register rx handler: " + err.Error())
	}
	err = dev.StartRxSingle()
	if err != nil {
		panic("unable to start rx: " + err.Error())
	}
	var lastSend time.Time
	var seq uint16
	var pc pcap.PacketBreakdown
	var pcfmt pcap.Formatter
	var frms []pcap.Frame
	var printdata []byte
	for {
		if rxgot > 0 {
			n := rxgot
			rxgot = 0 // Reset before processing to avoid reprocessing.
			copy(rxbufoffload[:], rxbuf[:n])
			// Immediately start another receive.
			err = dev.StartRxSingle()
			if err != nil {
				println("start rx fail: ", err.Error())
			}
			frms, err = pc.CaptureEthernet(frms[:0], rxbufoffload[:n], 0)
			if err != nil {
				println("pcap failed:", err.Error())
			}
			printdata, err = pcfmt.FormatFrames(printdata[:0], frms, rxbufoffload[:n])
			if err != nil {
				println("pcap format failed: ", err.Error())
			}
			printdata = append(printdata, '\n')
			serialWrite(printdata)
		}
		if time.Since(lastSend) > time.Second {
			lastSend = time.Now()
			n := putTestFrame(txbuf[:], seq)
			seq++
			err = dev.SendFrame(txbuf[:n])
			if err != nil {
				println("send tx fail: " + err.Error())
			} else if seq%10 == 5 {
				println("sent out tx #", seq)
			}
		}
	}
}

// putTestFrame builds an ICMP echo request (ping) packet and returns the total frame length.
func putTestFrame(dst []byte, seq uint16) int {
	const (
		ethHeaderLen  = 14
		ipHeaderLen   = 20
		icmpHeaderLen = 8
		icmpDataLen   = 32
		ipTotalLen    = ipHeaderLen + icmpHeaderLen + icmpDataLen
		flagDF        = 0x4000 // Don't Fragment flag.
	)

	// Build Ethernet frame.
	e, _ := ethernet.NewFrame(dst)
	*e.DestinationHardwareAddr() = ethernet.BroadcastAddr()
	*e.SourceHardwareAddr() = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	e.SetEtherType(ethernet.TypeIPv4)

	// Build IPv4 frame.
	ifrm, _ := ipv4.NewFrame(e.Payload())
	ifrm.SetVersionAndIHL(4, 5) // IPv4, 20-byte header (no options).
	ifrm.SetTotalLength(ipTotalLen)
	ifrm.SetID(seq)
	ifrm.SetFlags(flagDF)
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoICMP)
	*ifrm.SourceAddr() = [4]byte{192, 168, 1, 100}
	*ifrm.DestinationAddr() = [4]byte{192, 168, 1, 1}
	ifrm.SetCRC(0)
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())

	// Build ICMP echo request.
	icmp, _ := icmpv4.NewFrame(ifrm.Payload())
	icmp.SetType(icmpv4.TypeEcho)
	icmp.SetCode(0)
	echo := icmpv4.FrameEcho{Frame: icmp}
	echo.SetIdentifier(0x1234)
	echo.SetSequenceNumber(seq)
	// Fill ICMP data with pattern.
	for i := range echo.Data()[:icmpDataLen] {
		echo.Data()[i] = byte(i)
	}
	// Calculate ICMP checksum.
	var crc lneto.CRC791
	icmpCRC := crc.PayloadSum16(ifrm.Payload())
	icmp.SetCRC(icmpCRC)
	plen := ethHeaderLen + ipTotalLen
	crcEth := ethernet.CRC32(dst[:plen])
	binary.LittleEndian.PutUint32(dst[plen:], crcEth)
	return plen + 4
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
