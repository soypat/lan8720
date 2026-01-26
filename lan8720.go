// Package lan8720 provides a driver for the LAN8720 Ethernet PHY transceiver.
//
// The LAN8720 is a low-power 10BASE-T/100BASE-TX Ethernet PHY commonly used
// with RMII (Reduced Media Independent Interface) to connect microcontrollers
// to Ethernet networks. This package provides abstractions for configuring
// the PHY and interfacing with RMII hardware implementations.
package lan8720

import (
	"errors"
	"time"

	"github.com/soypat/lneto/phy"
)

// Config holds the configuration parameters for initializing a LAN8720 device.
type Config struct {
	// PHYAddr is the MDIO address of the PHY. Most LAN8720 breakout boards
	// use address 1 by default, but this can vary based on hardware strapping.
	// Valid range is 0-31.
	PHYAddr uint8
	// Advertisement is the autonegotiation mode.
	Advertisement phy.ANAR
}

// RMIISingle combines both receive and transmit capabilities for single-frame
// RMII operation. This interface is suitable for simple, non-concurrent
// Ethernet communication where frames are processed one at a time.
type RMIISingle interface {
	RMIIRxSingle
	RMIITxSingle
}

// RMIITxSingle defines the interface for transmitting Ethernet frames over
// RMII in single-frame mode. Implementations handle the low-level timing
// and signaling required by the RMII specification.
type RMIITxSingle interface {
	// IsSending returns true if a frame transmission is currently in progress.
	// Use this to poll for transmission completion before sending another frame.
	IsSending() bool
	// SendFrame transmits a single Ethernet frame over RMII. The frame should
	// contain a complete Ethernet frame (destination MAC, source MAC, EtherType,
	// and payload). The implementation handles preamble, SFD, and CRC generation.
	// Returns an error if transmission cannot be initiated (e.g., busy).
	SendFrame(frame []byte) error
}

// RMIIRxSingle defines the interface for receiving Ethernet frames over RMII
// in single-frame mode. After receiving a frame, the receiver stops listening
// until explicitly restarted, allowing the application to process the frame
// without buffer overrun concerns.
type RMIIRxSingle interface {
	// StopRx stops the receiver and aborts any ongoing reception.
	// Returns an error if the receiver is already stopped.
	StopRx() error
	// StartRxSingle enables asynchronous reception of a single frame.
	// After a frame is received, the RMII receiver automatically stops
	// and invokes the callback set via SetRxHandler. Call StartRxSingle
	// again to receive the next frame.
	StartRxSingle() error
	// SetRxHandler configures the receive buffer and callback function.
	// When a frame is received, the callback is invoked with the portion
	// of rxbuf containing the received data. Must be called before StartRxSingle.
	SetRxHandler(rxbuf []byte, callback func(buf []byte)) (err error)
	// InRx returns true if the receiver is actively listening for a frame
	// (i.e., StartRxSingle was called and no frame has been received yet).
	InRx() bool
}

// PHY represents a LAN8720 Ethernet PHY. It wraps the generic PHY device
// from the phy package and provides LAN8720-specific functionality.
// Use Configure to initialize the device before use.
type PHY struct {
	phy.Device
}

// Configure initializes the LAN8720 device with the given MDIO bus and configuration.
// The mdio parameter provides access to the PHY's management registers.
// This must be called before using any other Device methods.
func (d *PHY) Configure(mdio phy.MDIOBus, cfg Config) (err error) {
	if cfg.Advertisement == 0 {
		return errors.New("invalid advertisement")
	}
	p := &d.Device
	p.ConfigureAs22(mdio, cfg.PHYAddr)
	err = p.ResetPHY()
	if err != nil {
		return err
	}
	err = p.SetAdvertisement(cfg.Advertisement)
	if err != nil {
		return err
	}
	err = p.EnableAutoNegotiation(true)
	if err != nil {
		return err
	}
	return nil
}

// WaitAutoNegotiation waits for auto-negotiation to complete and link to establish.
// The timeout specifies the maximum duration to wait. On success, returns the
// negotiated link mode. Returns an error if timeout expires or PHY communication fails.
//
// It is suggested the timeout be at least 2 seconds to give LAN8720 enough time to autonegotiate.
func (d *PHY) WaitAutoNegotiation(timeout time.Duration) (phy.LinkMode, error) {
	deadline := time.Now().Add(timeout)
	linkUp, err := d.Device.WaitForLinkWithDeadline(deadline)
	if err != nil {
		return phy.LinkDown, err
	}
	if !linkUp {
		return phy.LinkDown, errors.New("auto-negotiation timeout")
	}
	return d.Device.NegotiatedLink()
}

// DeviceSingle combines a LAN8720 PHY with single-frame RMII transmit and
// receive capabilities. This is the primary type for applications that need
// complete Ethernet PHY functionality with simple frame-by-frame operation.
type DeviceSingle struct {
	PHY
	RMIISingle
}

func (ds *DeviceSingle) Configure(mdio phy.MDIOBus, rmii RMIISingle, cfg Config) error {
	err := ds.PHY.Configure(mdio, cfg)
	if err != nil {
		return err
	}
	ds.RMIISingle = rmii
	return nil
}
