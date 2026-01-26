//go:build rp2040 || rp2350

package lan8720

import (
	"errors"
	"machine"
	"time"

	"github.com/soypat/lneto/phy"
	pio "github.com/tinygo-org/pio/rp2-pio"
	"github.com/tinygo-org/pio/rp2-pio/piolib"
)

// PicoConfig holds configuration for creating a LAN8720 device on RP2040/RP2350.
type PicoConfig struct {
	// PIO is the PIO peripheral to use for RMII state machines.
	// Use pio.PIO0 or pio.PIO1.
	PIO *pio.PIO
	// PHYAddr is the MDIO address of the PHY (typically 1 for LAN8720 breakouts).
	PHYConfig Config
	// MDC is the MDIO clock pin.
	MDC machine.Pin
	// MDIO is the MDIO data pin.
	MDIO machine.Pin
	// TxConfig configures the RMII transmit path.
	TxConfig piolib.RMIITxConfig
	// RxConfig configures the RMII receive path.
	RxConfig piolib.RMIIRxConfig
}

// picoRMIISingle adapts piolib.RMIITx and piolib.RMIIRx to the RMIISingle interface.
type picoRMIISingle struct {
	tx piolib.RMIITx
	rx piolib.RMIIRx
}

// RMIITxSingle implementation.

func (p *picoRMIISingle) IsSending() bool {
	return p.tx.IsSending()
}

func (p *picoRMIISingle) SendFrame(frame []byte) error {
	return p.tx.SendFrame(frame)
}

// RMIIRxSingle implementation.

func (p *picoRMIISingle) StopRx() error {
	return p.rx.StopRx()
}

func (p *picoRMIISingle) StartRxSingle() error {
	return p.rx.StartRx()
}

func (p *picoRMIISingle) SetRxHandler(rxbuf []byte, callback func(buf []byte)) error {
	return p.rx.SetRxIRQHandler(rxbuf, callback)
}

func (p *picoRMIISingle) InRx() bool {
	return p.rx.InRx()
}

// NewPicoLAN8720Single creates and configures a DeviceSingle for RP2040/RP2350.
// It sets up MDIO bit-bang communication for PHY management and PIO-based
// RMII state machines for frame transmission and reception.
func NewPicoLAN8720Single(cfg PicoConfig) (*DeviceSingle, error) {
	mdiomsk := (1 << cfg.MDC) | (1 << cfg.MDIO)
	// clkmsk := (1 << pinRefClk)
	txmsk := 0b111 << cfg.TxConfig.TxBase
	rxmsk := 0b111 << cfg.RxConfig.RxBase
	aliased := rxmsk & txmsk & mdiomsk //& clkmsk
	if aliased != 0 {
		return nil, errors.New("aliased pins, check pin definitions")
	}
	// Configure MDIO bit-bang interface.
	mdio := makeMDIO(cfg.MDC, cfg.MDIO)

	// Configure PIO-based RMII.
	rmii := &picoRMIISingle{}
	err := rmii.rx.Configure(cfg.PIO, cfg.RxConfig)
	if err != nil {
		return nil, err
	}
	err = rmii.tx.Configure(cfg.PIO, cfg.TxConfig)
	if err != nil {
		return nil, err
	}

	// Create and configure the device.
	var dev DeviceSingle
	err = dev.Configure(mdio, rmii, cfg.PHYConfig)
	if err != nil {
		return nil, err
	}
	return &dev, nil
}

// makeMDIO sets up MDIO bit-bang interface for PHY register access.
func makeMDIO(pinMDC, pinMDIO machine.Pin) *phy.MDIOBitBang {
	const mdioDelay = 340 * time.Nanosecond // MDIO spec max turnaround time

	pinMDIO.Configure(machine.PinConfig{Mode: machine.PinInputPullup})
	pinMDC.Configure(machine.PinConfig{Mode: machine.PinOutput})
	pinMDC.Low()

	var bus phy.MDIOBitBang
	bus.Configure(
		func(outBit bool) {
			// sendBit: set data, clock high, clock low
			if outBit {
				pinMDIO.Configure(machine.PinConfig{Mode: machine.PinInputPullup})
			} else {
				pinMDIO.Low()
				pinMDIO.Configure(machine.PinConfig{Mode: machine.PinOutput})
			}
			time.Sleep(mdioDelay)
			pinMDC.High()
			time.Sleep(mdioDelay)
			pinMDC.Low()
		},
		func() bool {
			// getBit: clock high, read, clock low
			time.Sleep(mdioDelay)
			pinMDC.High()
			time.Sleep(mdioDelay)
			pinMDC.Low()
			return pinMDIO.Get()
		},
		func(setOut bool) {
			// setDir: configure pin direction
			if setOut {
				pinMDIO.Configure(machine.PinConfig{Mode: machine.PinInputPullup})
			} else {
				pinMDIO.Configure(machine.PinConfig{Mode: machine.PinInput})
			}
		},
	)
	return &bus
}
