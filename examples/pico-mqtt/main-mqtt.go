package main

import (
	"context"
	"io"
	"log/slog"
	"machine"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/soypat/lan8720"
	"github.com/soypat/lan8720/examples/lannet"
	"github.com/soypat/lneto/phy"
	"github.com/soypat/lneto/tcp"
	mqtt "github.com/soypat/natiu-mqtt"
	pio "github.com/tinygo-org/pio/rp2-pio"
	"github.com/tinygo-org/pio/rp2-pio/piolib"
)

const (
	connectTimeout = 5 * time.Second
	dhcpTimeout    = 7000 * time.Millisecond
	dhcpRetries    = 3

	mqttPort = 1883

	linkmode     = phy.Link100FDX
	netPollSleep = 5 * time.Millisecond

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
	topic    = []byte("mytopic")
	led      = machine.LED
	mqttAddr = [4]byte{54, 36, 178, 49} // https://test.mosquitto.org/
	connvar  mqtt.VariablesConnect      // Set below.
	subVar   = mqtt.VariablesSubscribe{
		TopicFilters: []mqtt.SubscribeRequest{
			{TopicFilter: topic, QoS: mqtt.QoS0},
		},
	}
	packetFlags, _ = mqtt.NewPublishFlags(mqtt.QoS0, false, false)
	pubVar         = mqtt.VariablesPublish{
		TopicName: topic,
	}
)

func main() {
	time.Sleep(2 * time.Second)
	println("starting HTTP server example")
	logger := slog.New(slog.NewTextHandler(machine.Serial, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	// Configure LED.
	led.Configure(machine.PinConfig{Mode: machine.PinOutput})
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
	llstack := stack.LnetoStack()
	rstack := llstack.StackRetrying(netPollSleep)
	results, err := rstack.DoDHCPv4([4]byte{}, dhcpTimeout, dhcpRetries)
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

	client := mqtt.NewClient(mqtt.ClientConfig{
		Decoder: mqtt.DecoderNoAlloc{UserBuffer: make([]byte, 4096)},
		OnPub: func(pubHead mqtt.Header, varPub mqtt.VariablesPublish, r io.Reader) error {
			payload, err := io.ReadAll(r)
			if err != nil {
				logger.Error("OnPub: failed to read payload", slog.String("err", err.Error()))
				return err
			}
			logger.Info("mqttrx", slog.String("msg", string(payload)))
			return nil
		},
	})
	var conn tcp.Conn
	err = conn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, 1024),
		TxBuf:             make([]byte, 1024),
		TxPacketQueueSize: 3,
		Logger:            logger,
	})
	if err != nil {
		panic("TCP config: " + err.Error())
	}

	for {
		if !conn.State().IsClosed() {
			conn.Abort()
		}
		err = rstack.DoDialTCP(&conn, uint16(llstack.Prand32()), netip.AddrPortFrom(netip.AddrFrom4(mqttAddr), mqttPort), connectTimeout, 6)
		if err != nil {
			llstack.DebugErr("failed dial TCP", err.Error())
			println("\n\n\n TCP FAILED\n\n\n")
			time.Sleep(time.Second)
			continue
		}
		handleConn(&conn, client)
		if err := client.Err(); err != nil {
			println("mqtt disconnect:", err.Error())
		} else {
			println("no mqtt disconnect error, likely no connection established")
		}
		conn.Close()
		time.Sleep(time.Second)
	}
}

func handleConn(conn *tcp.Conn, client *mqtt.Client) {
	defer client.Disconnect(net.ErrClosed)
	defer led.Low()
	connvar.SetDefaultMQTT([]byte("lan8720-dude"))
	err := client.StartConnect(conn, &connvar)
	if err != nil {
		return
	}
	retries := 50
	lastLedState := false
	for retries > 0 && !client.IsConnected() {
		lastLedState = !lastLedState
		led.Set(lastLedState)

		time.Sleep(100 * time.Millisecond)
		err = client.HandleNext()
		if err != nil {
			println("mqtt:handle-next-failed", err.Error())
		}
		retries--
	}

	if !client.IsConnected() {
		println("retries exceeded")
		return
	}
	led.High() // solid LED state to indicate connection.
	ctx, cancelCtx := context.WithTimeout(context.Background(), 5*time.Second)
	err = client.Subscribe(ctx, subVar)
	cancelCtx()
	if err != nil {
		println("subscribe failed:", err.Error())
		return
	} else if len(client.SubscribedTopics()) == 0 {
		println("no subscription?")
		return
	}
	var msgbuf [64]byte
	var lastTxPub time.Time
	for client.IsConnected() {
		now := time.Now()
		switch {
		case now.Sub(lastTxPub) > time.Second:
			msg := append(msgbuf[:0], "{\"heat\":"...)
			msg = strconv.AppendInt(msg, getValue(), 10)
			msg = append(msg, "}\n"...)
			err = client.PublishPayload(packetFlags, pubVar, msg)
			if err != nil {
				println("sending payload: ", err.Error())
			}
		case conn.AvailableInput() > 0:
			// TCP data available, try to read.
			err = client.HandleNext()
			if err != nil {
				println("handling data:", err.Error())
			}
		default:
			time.Sleep(time.Second) // Nothing to do.
		}
	}
}

func getValue() int64 {
	return 10
}

func loopForeverStack(stack *lannet.Stack) {
	for {
		send, recv, _ := stack.RecvAndSend()
		if send == 0 && recv == 0 {
			time.Sleep(netPollSleep)
		}
	}
}
