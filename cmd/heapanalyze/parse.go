package main

import (
	"regexp"
	"strconv"
	"strings"
)

// EntryKind classifies each line in the log.
type EntryKind uint8

const (
	KindAlloc   EntryKind = iota // [ALLOC] inc=N tot=N seqs
	KindLog                      // time=[...] LEVEL msg ... (heaplog format)
	KindSlog                     // time=YYYY-... level=LEVEL msg=... (slog format)
	KindPcap                     // NN.NNN RX|TX<len> Ethernet ...
	KindApp                      // plain text (packet drop, incoming connection, etc.)
	KindUnknown                  // serial header, blank, etc.
)

func (k EntryKind) String() string {
	switch k {
	case KindAlloc:
		return "ALLOC"
	case KindLog:
		return "LOG"
	case KindSlog:
		return "SLOG"
	case KindPcap:
		return "PCAP"
	case KindApp:
		return "APP"
	default:
		return "UNKNOWN"
	}
}

// Entry is one parsed line from the log. Preserves all original data.
type Entry struct {
	Line int       // 1-based line number in the file
	Kind EntryKind // what type of line this is
	Raw  string    // original line text

	// KindAlloc fields:
	AllocLabel   string // label after [ALLOC] (e.g. "StackIP.Demux:start", "seqs")
	AllocInc     int64  // bytes allocated since last [ALLOC]
	AllocN       int64  // number of allocations since last [ALLOC] (-1 if not available)
	AllocHeap    int64  // current HeapAlloc at this point (-1 if not available)
	AllocFree    int64  // free heap bytes (HeapSys-HeapInuse) at this point (-1 if not available)
	AllocTot     int64  // cumulative total bytes allocated

	// KindPcap fields:
	BootTime  float64 // seconds since boot (e.g. 7.188)
	Direction string  // "RX" or "TX"
	FrameLen  int     // frame length in bytes
	Proto     string  // highest-layer protocol: "TCP", "UDP", "ARP", "DHCPv4", "DNS", "NTP", "HTTP"
	TCPFlags  string  // TCP flags if present (e.g. "SYN", "RST,ACK")
	DstPort   int     // TCP/UDP destination port, 0 if N/A
	SrcPort   int     // TCP/UDP source port, 0 if N/A

	// KindLog / KindSlog fields:
	LogLevel string // "TRACE", "DEBUG", "INFO", "ERROR", "SEQS"
	LogMsg   string // the message field (e.g. "StackIP.Demux:start")
	LogAttrs string // remaining key=val pairs, raw
}

// AllocEvent ties one [ALLOC] entry to its surrounding context by index into Entries.
type AllocEvent struct {
	Idx      int     // index into Entries for the [ALLOC] line
	PrevIdx  int     // index of nearest preceding non-alloc Entry (-1 if none)
	NextIdx  int     // index of nearest following non-alloc Entry (-1 if none)
	BootTime float64 // inherited from nearest preceding pcap line
	Phase    string  // "init", "dhcp", "dns", "ntp", "listen-idle", "http-serving"
}

// ParseResult holds the complete parsed log.
type ParseResult struct {
	Entries []Entry      // all lines in order
	Allocs  []AllocEvent // allocation events in order
}

const allocMarker = "[ALLOC]"

var (
	reHeapLog   = regexp.MustCompile(`^time=\[([^\]]+)\]\s+(\S+)\s+(\S+)(.*)`)
	reSlogLog   = regexp.MustCompile(`^time=\S+\s+level=(\S+)\s+msg=("?)(.+)`)
	rePcap      = regexp.MustCompile(`^(\d+\.\d+)\s+(RX|TX)(\d+)\s+`)
	reTCPFlags  = regexp.MustCompile(`flags=([A-Z][A-Z,]*)`)
	reDstPort   = regexp.MustCompile(`\(Destination port\)=(\d+)`)
	reSrcPort   = regexp.MustCompile(`\(Source port\)=(\d+)`)
	reProtoHigh = regexp.MustCompile(`\|\s+(HTTP|DNS|NTP|DHCPv4|TCP|UDP|ARP|ICMP)\b`)
)

// parseAllocFields parses "[ALLOC] label key=val key=val ..." into an Entry.
// Returns the entry and true if successful.
func parseAllocFields(raw string) (Entry, bool) {
	e := Entry{Kind: KindAlloc, Raw: raw, AllocN: -1, AllocHeap: -1, AllocFree: -1}
	// Skip past "[ALLOC] ".
	rest := raw[len(allocMarker):]
	if len(rest) > 0 && rest[0] == ' ' {
		rest = rest[1:]
	}
	// First word without '=' is the label.
	if word, after, ok := strings.Cut(rest, " "); ok && !strings.Contains(word, "=") {
		e.AllocLabel = word
		rest = after
	}
	// Parse key=value pairs.
	for rest != "" {
		var token string
		token, rest, _ = strings.Cut(rest, " ")
		key, val, ok := strings.Cut(token, "=")
		if !ok || key == "" {
			continue
		}
		v, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "inc":
			e.AllocInc = v
		case "n":
			e.AllocN = v
		case "heap":
			e.AllocHeap = v
		case "free":
			e.AllocFree = v
		case "tot":
			e.AllocTot = v
		}
	}
	return e, true
}

// Parse processes raw log lines into a ParseResult.
func Parse(lines []string) ParseResult {
	var pr ParseResult
	pr.Entries = make([]Entry, 0, len(lines)+256) // extra capacity for embedded splits

	var lastBootTime float64
	phase := "init"

	for i, line := range lines {
		lineNum := i + 1

		// Check for embedded [ALLOC] anywhere in the line.
		if idx := strings.Index(line, allocMarker); idx >= 0 {
			before := strings.TrimSpace(line[:idx])
			// If there's content before the [ALLOC], emit it as its own entry first.
			if before != "" {
				e := parseSingleLine(before, lineNum)
				if e.Kind == KindPcap {
					lastBootTime = e.BootTime
				}
				updatePhase(e, &phase)
				pr.Entries = append(pr.Entries, e)
			}
			// Emit the alloc entry.
			if ae, ok := parseAllocFields(line[idx:]); ok {
				ae.Line = lineNum
				pr.Entries = append(pr.Entries, ae)
			}
			continue
		}

		e := parseSingleLine(line, lineNum)
		if e.Kind == KindPcap {
			lastBootTime = e.BootTime
		}
		updatePhase(e, &phase)
		pr.Entries = append(pr.Entries, e)
	}

	// Second pass: build AllocEvents with context indices.
	lastBootTime = 0
	phase = "init"
	for i := range pr.Entries {
		e := &pr.Entries[i]
		if e.Kind == KindPcap {
			lastBootTime = e.BootTime
		}
		if e.Kind != KindAlloc {
			updatePhase(*e, &phase)
			continue
		}

		ae := AllocEvent{
			Idx:      i,
			PrevIdx:  -1,
			NextIdx:  -1,
			BootTime: lastBootTime,
			Phase:    phase,
		}

		// Walk backward for nearest non-alloc.
		for j := i - 1; j >= 0; j-- {
			if pr.Entries[j].Kind != KindAlloc {
				ae.PrevIdx = j
				break
			}
		}
		// Walk forward for nearest non-alloc.
		for j := i + 1; j < len(pr.Entries); j++ {
			if pr.Entries[j].Kind != KindAlloc {
				ae.NextIdx = j
				break
			}
		}

		pr.Allocs = append(pr.Allocs, ae)
	}

	return pr
}

// parseSingleLine classifies and parses a single non-ALLOC line.
func parseSingleLine(line string, lineNum int) Entry {
	e := Entry{Line: lineNum, Raw: line}

	// Try pcap first (most common line type).
	if m := rePcap.FindStringSubmatch(line); m != nil {
		e.Kind = KindPcap
		e.BootTime, _ = strconv.ParseFloat(m[1], 64)
		e.Direction = m[2]
		e.FrameLen, _ = strconv.Atoi(m[3])
		e.Proto = extractHighestProto(line)
		if fm := reTCPFlags.FindStringSubmatch(line); fm != nil {
			e.TCPFlags = fm[1]
		}
		if pm := reDstPort.FindStringSubmatch(line); pm != nil {
			e.DstPort, _ = strconv.Atoi(pm[1])
		}
		if pm := reSrcPort.FindStringSubmatch(line); pm != nil {
			e.SrcPort, _ = strconv.Atoi(pm[1])
		}
		return e
	}

	// Try heaplog time= format: time=[MM-DD HH:MM:SS.mmm] LEVEL msg ...
	if m := reHeapLog.FindStringSubmatch(line); m != nil {
		e.Kind = KindLog
		e.LogLevel = m[2]
		e.LogMsg = m[3]
		e.LogAttrs = strings.TrimSpace(m[4])
		return e
	}

	// Try slog format: time=YYYY-... level=LEVEL msg=...
	if m := reSlogLog.FindStringSubmatch(line); m != nil {
		e.Kind = KindSlog
		e.LogLevel = m[1]
		msg := m[3]
		// If msg was quoted, extract until closing quote.
		if m[2] == `"` {
			if idx := strings.Index(msg, `"`); idx >= 0 {
				e.LogAttrs = strings.TrimSpace(msg[idx+1:])
				msg = msg[:idx]
			}
		} else {
			// Unquoted: msg is until first space with key=val.
			if idx := strings.Index(msg, " "); idx >= 0 {
				rest := msg[idx+1:]
				if strings.Contains(rest, "=") {
					e.LogAttrs = rest
					msg = msg[:idx]
				}
			}
		}
		e.LogMsg = msg
		return e
	}

	// Known app messages.
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		e.Kind = KindUnknown
		return e
	}
	if strings.HasPrefix(trimmed, "Connected to") ||
		strings.HasPrefix(trimmed, "starting HTTP server") {
		e.Kind = KindApp
		return e
	}
	if strings.HasPrefix(trimmed, "packet drop") ||
		strings.HasPrefix(trimmed, "incoming connection") ||
		strings.HasPrefix(trimmed, "Got webpage") ||
		strings.HasPrefix(trimmed, "got toggle") ||
		strings.HasPrefix(trimmed, "read error") ||
		strings.HasPrefix(trimmed, "Retrying DHCP") ||
		strings.HasPrefix(trimmed, "ERROR RX") {
		e.Kind = KindApp
		return e
	}

	// Fallback: treat any non-empty line as app.
	e.Kind = KindApp
	return e
}

// extractHighestProto finds the highest-layer protocol mentioned in a pcap line.
func extractHighestProto(line string) string {
	// Find all protocol matches, return the last (highest layer).
	matches := reProtoHigh.FindAllStringSubmatch(line, -1)
	if len(matches) > 0 {
		return matches[len(matches)-1][1]
	}
	return "ETH"
}

// updatePhase transitions the phase state machine based on line content.
func updatePhase(e Entry, phase *string) {
	switch {
	case *phase == "init" && e.Kind == KindPcap && e.Direction == "TX" && e.Proto == "DHCPv4":
		*phase = "dhcp"
	case strings.Contains(e.Raw, "DHCP complete"):
		*phase = "post-dhcp"
	case strings.Contains(e.Raw, "resolving NTP host") || strings.Contains(e.Raw, "resolving DNS"):
		*phase = "dns"
	case strings.Contains(e.Raw, "DNS resolved"):
		*phase = "post-dns"
	case strings.Contains(e.Raw, "starting NTP request"):
		*phase = "ntp"
	case strings.Contains(e.Raw, "NTP complete"):
		*phase = "post-ntp"
	case strings.Contains(e.Raw, "msg=listening"):
		*phase = "listen-idle"
	case strings.Contains(e.Raw, "listener:tryaccept"):
		*phase = "http-serving"
	case *phase == "http-serving" && strings.Contains(e.Raw, "TCPConn.Close:done"):
		*phase = "listen-idle"
	}
}

// Summarize reduces an entry to a short string useful for grouping.
func Summarize(e Entry) string {
	switch e.Kind {
	case KindLog:
		return e.LogLevel + " " + e.LogMsg
	case KindSlog:
		return e.LogLevel + " " + e.LogMsg
	case KindPcap:
		s := e.Direction + " " + e.Proto
		if e.TCPFlags != "" {
			s += " " + e.TCPFlags
		}
		if e.DstPort != 0 {
			s += " dport=" + strconv.Itoa(e.DstPort)
		}
		return s
	case KindApp:
		r := e.Raw
		if len(r) > 60 {
			r = r[:60] + "..."
		}
		return r
	default:
		return "(unknown)"
	}
}
