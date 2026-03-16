# Heap Allocation RCA — lim.log

**Date:** 2026-03-14
**Duration:** 2,320s (~39 min), timestamps 49998–52318s since boot
**Total alloc delta:** 58,021 bytes across 209 `[ALLOC]` events
**Free heap range:** 752–48,912 bytes
**Connections:** ~81 accepted on port 80

## Overview

This log captures heap allocation behavior with `debugheaplog` build tag enabled.
The `[ALLOC]` lines are emitted by `internal.LogAllocs()` which calls
`runtime.ReadMemStats` and reports the delta since the last checkpoint:

```
[ALLOC] <label> inc=<bytes_allocated> n=<mallocs> heap=<HeapAlloc> free=<HeapSys-HeapInuse> tot=<TotalAlloc>
```

No `http:appendhdr` allocations appear in this log (unlike the logs2.out 5-hour run),
so this capture focuses on the **pcap formatting** and **packet processing** paths.

## Allocation Sources

| Label | Count | Total Bytes | Avg inc | Source |
|-------|------:|------------:|--------:|--------|
| `pcap:fmtfield:append-done` | 47 | 29,496 | 627 | `pcap/format.go:151` — `formatField()` |
| `pcap:fmtframe:done` | 47 | 26,616 | 566 | `pcap/format.go:100` — `FormatFrame()` |
| `pcap:ipv4:proto-crc-done` | 107 | 1,712 | 16 | `pcap/capture.go:273` — `CaptureIPv4()` |
| `cbnode:pre-demux` | 3 | 132 | 44 | `definitions_tinygo.go:24` — `cbnode.Demux()` |
| `LinkStack:drop-packet` | 4 | 75 | ~19 | `stack-ethernet.go:142` — `StackEthernet.Demux()` |
| `pcap:ipproto:start` | 1 | 16 | 16 | `pcap/capture.go:278` — `captureIPProto()` |
| **Total** | **209** | **58,047** | | |

---

## 1. `pcap:fmtfield:append-done` — 29.5KB (51% of allocations)

### What allocates

`formatField()` calls `appendField(f.buf[:0], pkt, ...)` to extract bit-level protocol
field data from the raw packet into a scratch buffer. `appendField()` uses multiple
`append()` calls to build up the extracted bytes:

```go
// pcap/format.go:145-151
f.mubuf.Lock()
defer f.mubuf.Unlock()
f.buf, err = appendField(f.buf[:0], pkt, field.FrameBitOffset+pktStartOff, field.BitLength, field.Flags.IsRightAligned())
if err != nil {
    return dst, err
}
debuglog("pcap:fmtfield:append-done")
```

Inside `appendField()` (pcap/capture.go:727-780), the `dst` byte slice grows via append:

```go
// Byte-aligned fast path (line 741):
dst = append(dst, pkt[octetsStart:octetsStart+octets]...)

// Right-aligned fields like TCP flags (lines 752-753):
dst = append(dst, pkt[octetsStart]&mask)
dst = append(dst, pkt[octetsStart+1:octetsStart+octets]...)

// Left-aligned bit extraction loop (line 774):
dst = append(dst, b)
```

Despite `f.buf[:0]` reusing the slice header, the underlying capacity is not always
sufficient for the field data, causing heap growth on each `append` beyond capacity.

### Log evidence

Each RX/TX packet triggers one `fmtfield` alloc per formatted frame. The `inc` varies
with field count — 456B for small frames (19 mallocs), 744B for large ones (31 mallocs):

```
50001.324 RX143 Ethernet ... | IPv6 ... | UDP ...
time=[03-14 02:46:03.865] INFO LinkStack:drop-packet dsthw=56294136414210 ethertype=IPv6
packet drop
[ALLOC] pcap:fmtfield:append-done inc=744 n=31 heap=228704 free=3184 tot=1366437
[ALLOC] pcap:fmtframe:done inc=528 n=22 heap=229408 free=2480 tot=1366965
50001.343 RX90 Ethernet ... | IPv6 ... | unknown proto ...
```

Note how `fmtfield` and `fmtframe` fire as a pair — field extraction followed by
frame assembly — eating 1,272 bytes for a single dropped IPv6 packet that nobody reads.

### Near-OOM example

Three consecutive packets drove free heap from 5,008 down to 752 bytes:

```
[ALLOC] pcap:fmtfield:append-done inc=456 n=19 heap=226880 free=5008 tot=1365069
[ALLOC] pcap:fmtframe:done inc=624 n=26 heap=227712 free=4176 tot=1365693
   ...
[ALLOC] pcap:fmtfield:append-done inc=744 n=31 heap=230400 free=1488 tot=1367709
[ALLOC] pcap:fmtframe:done inc=528 n=22 heap=231104 free=784  tot=1368237
   ...
[ALLOC] pcap:ipv4:proto-crc-done inc=16 n=1  heap=231136 free=752  tot=1368253
```

After this, a GC cycle fires and free jumps back to 48,624. But 752 bytes free on a
system with no virtual memory is dangerously close to OOM.

---

## 2. `pcap:fmtframe:done` — 26.6KB (46% of allocations)

### What allocates

`FormatFrame()` builds the human-readable packet line by appending protocol name,
field separator, field values, and error strings into a `dst []byte`:

```go
// pcap/format.go:56-101
func (f *Formatter) FormatFrame(dst []byte, frm Frame, pkt []byte) (_ []byte, err error) {
    dst = append(dst, frm.Protocol...)       // "Ethernet", "IPv4", "TCP", etc.
    dst = append(dst, " len="...)
    dst = strconv.AppendInt(dst, int64(bitlen/8), 10)
    for ifield := range frm.Fields {
        dst = append(dst, sep...)             // "; " between fields
        dst, err = f.FormatField(dst, ...)    // triggers fmtfield allocs too
    }
    if len(frm.Errors) > 0 {
        dst = append(dst, " errs=("...)
        for i, err := range frm.Errors {
            dst = append(dst, err.Error()...) // error string allocs
        }
        dst = append(dst, ')')
    }
    debuglog("pcap:fmtframe:done")
```

The `dst` slice grows across the entire frame formatting. A typical Ethernet+IPv4+TCP
frame with ~20 fields produces the full line like:

```
50038.033 TX64 Ethernet len=14; destination=e8:4d:74:9f:61:4a; source=02:00:00:00:00:01;
protocol=0x0800 | IPv4 len=20; version=0x04; ... | TCP len=20; (Source port)=80; ...
```

That single line costs 744+456 = 1,200 bytes of heap allocations.

### Log evidence

The `fmtframe:done` alloc always follows `fmtfield:append-done` as a pair:

```
[ALLOC] pcap:fmtfield:append-done inc=744 n=31 heap=184896 free=46992 tot=1370210
[ALLOC] pcap:fmtframe:done inc=744 n=31 heap=185888 free=46000 tot=1370954
```

```
[ALLOC] pcap:fmtfield:append-done inc=456 n=19 heap=186752 free=45136 tot=1371538
[ALLOC] pcap:fmtframe:done inc=624 n=26 heap=187584 free=44304 tot=1372162
```

The variation in `inc` (456–744) and `n` (19–31) correlates with protocol complexity:
simple Ethernet-only frames are cheaper; Ethernet+IPv4+TCP+payload frames are most expensive.

---

## 3. `pcap:ipv4:proto-crc-done` — 1.7KB (3% of allocations)

### What allocates

`CaptureIPv4()` validates transport-layer checksums and collects errors into a nil slice:

```go
// pcap/capture.go:234-274
var protoErrs []error          // nil slice — zero cap
var crc lneto.CRC791
switch proto {
case lneto.IPProtoTCP:
    ...
    if crc.PayloadSum16(payload) != 0 {
        protoErrs = append(protoErrs, lneto.ErrBadCRC)  // heap alloc: nil → cap 1
    }
case lneto.IPProtoUDP:
    ...
        if crc.PayloadSum16(ufrm.RawData()[:frameLen]) != 0 {
            protoErrs = append(protoErrs, lneto.ErrBadCRC)
        }
case lneto.IPProtoICMP:
    ...
        if crc.PayloadSum16(payload) != 0 {
            protoErrs = append(protoErrs, lneto.ErrBadCRC)
        }
}
debuglog("pcap:ipv4:proto-crc-done")
return pc.captureIPProto(proto, dst, pkt, end, protoErrs...)
```

Every invocation allocates exactly 16 bytes (1 malloc) — even when `protoErrs` stays nil.
The 16B is likely the `CRC791` struct or an internal runtime allocation from the
`ReadMemStats` call itself within `debuglog`.

### Log evidence

Perfectly uniform — always `inc=16 n=1`, 107 times:

```
[ALLOC] pcap:ipv4:proto-crc-done inc=16 n=1 heap=231136 free=752  tot=1368253
[ALLOC] pcap:ipv4:proto-crc-done inc=16 n=1 heap=185920 free=45968 tot=1370970
[ALLOC] pcap:ipv4:proto-crc-done inc=16 n=1 heap=185952 free=45936 tot=1370986
[ALLOC] pcap:ipv4:proto-crc-done inc=16 n=1 heap=185984 free=45904 tot=1371002
[ALLOC] pcap:ipv4:proto-crc-done inc=16 n=1 heap=186016 free=45872 tot=1371018
[ALLOC] pcap:ipv4:proto-crc-done inc=16 n=1 heap=186048 free=45840 tot=1371034
```

Note the steady 16-byte staircase: heap increments by exactly 16 each time, free
decrements by exactly 16. This is a per-IPv4-packet cost on the hot path.

---

## 4. Minor Allocations

### `cbnode:pre-demux` — 132B (3 events)

Callback node demultiplexing in `definitions_tinygo.go:24`. Each event allocates 44B
(2 mallocs). Appears correlated with malformed packets:

```
ERROR RX: invalid length field at bits 96..100[ALLOC] cbnode:pre-demux inc=44 n=2 heap=197568 free=34320 tot=1379542
ERROR RX: invalid length field at bits 96..100[ALLOC] cbnode:pre-demux inc=44 n=2 heap=197760 free=34128 tot=1379650
```

### `LinkStack:drop-packet` — 75B (4 events)

slog attribute formatting in `StackEthernet.Demux()` when dropping packets. The
`slog.String("ethertype", efrm.EtherTypeOrSize().String())` call allocates for the
`.String()` conversion:

```
[ALLOC] LinkStack:drop-packet inc=26 n=3 heap=226272 free=5616 tot=1364613
time=[03-14 02:46:01.253] INFO LinkStack:drop-packet dsthw=233165495470600 ethertype=Type(19276)
packet drop
```

### `pcap:ipproto:start` — 16B (1 event)

Single checkpoint in `captureIPProto()`. Negligible.

---

## Fix Recommendations

### Priority 1: Disable pcap formatting in production

The pcap pretty-printer (`fmtfield` + `fmtframe`) accounts for **97%** of allocations
in this log. Most formatted packets are immediately dropped (IPv6, mDNS, SSDP) and
the output goes to serial which may not even be monitored. Gate pcap formatting behind
a build tag or runtime flag so it's off by default.

### Priority 2: Pre-size `appendField` scratch buffer

If pcap stays enabled, give `Formatter.buf` a fixed backing array to avoid growth:

```go
type Formatter struct {
    bufBacking [64]byte   // max field size
    buf        []byte
    // ...
}

func NewFormatter() Formatter {
    f := Formatter{}
    f.buf = f.bufBacking[:0]
    return f
}
```

This eliminates the `fmtfield` heap allocs entirely — fields are extracted into
stack-backed storage.

### Priority 3: Stack-local `protoErrs` backing

Avoid the nil-slice-to-heap-alloc on every IPv4 packet:

```go
var protoErrsBuf [1]error
protoErrs := protoErrsBuf[:0]
```

This keeps the common case (0 or 1 CRC errors) on the stack. Saves 16B × 107 = 1,712B
per log window, and eliminates a per-packet malloc on the hot path.

### Priority 4: Lazy slog in drop-packet

Skip the `.String()` allocation for dropped packets by using a numeric slog attribute
or by checking log level before formatting:

```go
if ls.handlers.enabled(slog.LevelInfo) {
    ls.handlers.info("LinkStack:drop-packet", ...)
}
```
