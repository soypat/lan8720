module github.com/soypat/lan8720

go 1.24

require (
	github.com/soypat/lneto v0.0.0-20260125121108-e83665f147b5
	github.com/tinygo-org/pio v0.2.0
)

replace github.com/tinygo-org/pio => ../pio
replace github.com/soypat/lneto  => ../lneto