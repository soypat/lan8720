package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	var input *os.File
	if len(os.Args) > 1 {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "open: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		input = f
	} else {
		input = os.Stdin
	}

	lines := readLines(input)
	pr := Parse(lines)

	totalBytes, count, dur := Summary(pr)
	printSummary(totalBytes, count, dur)

	groups := GroupByContext(pr)
	printContextGroups(groups, totalBytes)

	hist := IncHistogram(pr)
	printHistogram(hist, totalBytes)

	callsites := GroupByNextMsg(pr)
	printCallsites(callsites, totalBytes)

	phases := PhaseBreakdown(pr)
	printPhases(phases, totalBytes)

	ts := TimeSeries(pr, 5.0)
	printTimeSeries(ts)
}

func readLines(f *os.File) []string {
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // handle long pcap lines
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func printSummary(totalBytes int64, count int, dur float64) {
	fmt.Println("=== Heap Allocation Analysis ===")
	fmt.Printf("Total: %s across %d allocation events\n", fmtBytes(totalBytes), count)
	if dur > 0 {
		fmt.Printf("Duration: %.1fs   Rate: %s/sec\n", dur, fmtBytes(int64(float64(totalBytes)/dur)))
	}
	fmt.Println()
}

func printContextGroups(groups []AllocGroup, totalBytes int64) {
	fmt.Println("=== Top Allocation Sources (prev context → next log message) ===")
	fmt.Printf("  %-4s  %12s  %6s  %8s  %8s  %8s  %s\n",
		"#", "Total", "Count", "Avg", "Min", "Max", "Context")
	fmt.Println(strings.Repeat("-", 120))

	limit := len(groups)
	if limit > 30 {
		limit = 30
	}
	for i := 0; i < limit; i++ {
		g := groups[i]
		avg := g.TotalBytes / int64(g.Count)
		pct := 0.0
		if totalBytes > 0 {
			pct = float64(g.TotalBytes) / float64(totalBytes) * 100
		}
		fmt.Printf("  %-4d  %12s  %6d  %8s  %8s  %8s  %s  (%.1f%%)\n",
			i+1,
			fmtBytes(g.TotalBytes),
			g.Count,
			fmtBytes(avg),
			fmtBytes(g.MinInc),
			fmtBytes(g.MaxInc),
			truncate(g.Key, 70),
			pct,
		)
	}
	if len(groups) > limit {
		fmt.Printf("  ... and %d more groups\n", len(groups)-limit)
	}
	fmt.Println()
}

func printHistogram(hist []IncBucket, totalBytes int64) {
	fmt.Println("=== Inc Value Histogram ===")
	fmt.Printf("  %12s  %8s  %12s  %6s\n", "inc", "Count", "Total", "%")
	fmt.Println(strings.Repeat("-", 50))

	limit := len(hist)
	if limit > 25 {
		limit = 25
	}
	for i := 0; i < limit; i++ {
		b := hist[i]
		pct := 0.0
		if totalBytes > 0 {
			pct = float64(b.TotalBytes) / float64(totalBytes) * 100
		}
		fmt.Printf("  %12d  %8d  %12s  %5.1f%%\n", b.Inc, b.Count, fmtBytes(b.TotalBytes), pct)
	}
	if len(hist) > limit {
		fmt.Printf("  ... and %d more distinct values\n", len(hist)-limit)
	}
	fmt.Println()
}

func printCallsites(groups []AllocGroup, totalBytes int64) {
	fmt.Println("=== Per-LogAttrs Callsite (next log message after [ALLOC]) ===")
	fmt.Printf("  %-4s  %12s  %6s  %8s  %s\n", "#", "Total", "Count", "Avg", "Log Message")
	fmt.Println(strings.Repeat("-", 100))

	limit := len(groups)
	if limit > 20 {
		limit = 20
	}
	for i := 0; i < limit; i++ {
		g := groups[i]
		avg := g.TotalBytes / int64(g.Count)
		pct := 0.0
		if totalBytes > 0 {
			pct = float64(g.TotalBytes) / float64(totalBytes) * 100
		}
		fmt.Printf("  %-4d  %12s  %6d  %8s  %s  (%.1f%%)\n",
			i+1,
			fmtBytes(g.TotalBytes),
			g.Count,
			fmtBytes(avg),
			truncate(g.Key, 60),
			pct,
		)
	}
	if len(groups) > limit {
		fmt.Printf("  ... and %d more callsites\n", len(groups)-limit)
	}
	fmt.Println()
}

func printPhases(phases []PhaseStat, totalBytes int64) {
	fmt.Println("=== Phase Breakdown ===")
	fmt.Printf("  %-16s  %12s  %6s  %6s\n", "Phase", "Total", "Count", "%")
	fmt.Println(strings.Repeat("-", 50))

	for _, p := range phases {
		pct := 0.0
		if totalBytes > 0 {
			pct = float64(p.TotalBytes) / float64(totalBytes) * 100
		}
		fmt.Printf("  %-16s  %12s  %6d  %5.1f%%\n", p.Phase, fmtBytes(p.TotalBytes), p.Count, pct)
	}
	fmt.Println()
}

func printTimeSeries(buckets []TimeBucket) {
	if len(buckets) == 0 {
		return
	}

	fmt.Println("=== Allocation Rate (5-second buckets) ===")

	// Find max for scaling.
	var maxBytes int64
	for _, b := range buckets {
		if b.TotalBytes > maxBytes {
			maxBytes = b.TotalBytes
		}
	}
	if maxBytes == 0 {
		return
	}

	const barWidth = 50
	for _, b := range buckets {
		if b.Count == 0 {
			continue
		}
		barLen := int(float64(b.TotalBytes) / float64(maxBytes) * barWidth)
		if barLen < 1 && b.TotalBytes > 0 {
			barLen = 1
		}
		fmt.Printf("  %6.0f-%6.0fs  %s %s (%d allocs)\n",
			b.StartSec, b.EndSec,
			strings.Repeat("|", barLen),
			fmtBytes(b.TotalBytes),
			b.Count,
		)
	}
	fmt.Println()
}

// fmtBytes formats bytes with commas for readability.
func fmtBytes(b int64) string {
	if b < 0 {
		return "-" + fmtBytes(-b)
	}
	s := fmt.Sprintf("%d", b)
	// Insert commas.
	n := len(s)
	if n <= 3 {
		return s
	}
	var sb strings.Builder
	rem := n % 3
	if rem > 0 {
		sb.WriteString(s[:rem])
		if n > rem {
			sb.WriteByte(',')
		}
	}
	for i := rem; i < n; i += 3 {
		if i > rem {
			sb.WriteByte(',')
		}
		sb.WriteString(s[i : i+3])
	}
	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
