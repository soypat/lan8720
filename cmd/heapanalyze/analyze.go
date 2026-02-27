package main

import (
	"sort"
)

// AllocGroup aggregates allocations sharing a common grouping key.
type AllocGroup struct {
	Key        string  // grouping key (e.g. "RX TCP SYN → INFO StackIP.Demux:start")
	Count      int     // number of alloc events in this group
	TotalBytes int64   // sum of AllocInc
	MinInc     int64   // smallest single allocation
	MaxInc     int64   // largest single allocation
	Indices    []int   // indices into ParseResult.Allocs for drill-down
}

// IncBucket counts occurrences of a specific inc value.
type IncBucket struct {
	Inc        int64
	Count      int
	TotalBytes int64
}

// PhaseStat aggregates allocations by phase.
type PhaseStat struct {
	Phase      string
	Count      int
	TotalBytes int64
}

// TimeBucket aggregates allocations in a time window.
type TimeBucket struct {
	StartSec   float64
	EndSec     float64
	TotalBytes int64
	Count      int
}

// Summary returns overall statistics from the parse result.
func Summary(pr ParseResult) (totalBytes int64, count int, durationSec float64) {
	count = len(pr.Allocs)
	if count == 0 {
		return
	}
	last := pr.Allocs[count-1]
	totalBytes = pr.Entries[last.Idx].AllocTot
	// Duration from first to last boot time.
	first := pr.Allocs[0]
	durationSec = last.BootTime - first.BootTime
	if durationSec < 0 {
		durationSec = 0
	}
	return
}

// GroupByContext groups allocations by their (prevContext → nextMsg) pair.
// Returns slice sorted by TotalBytes descending.
func GroupByContext(pr ParseResult) []AllocGroup {
	type groupKey struct{ prev, next string }

	// Collect keys in order of first appearance to avoid map iteration order.
	var keyOrder []groupKey
	seen := make([]groupKey, 0, 64) // small working set
	groupIdx := make([]int, 0, 64)  // parallel: index into result for each key

	findGroup := func(k groupKey) int {
		for i, s := range seen {
			if s == k {
				return groupIdx[i]
			}
		}
		return -1
	}

	var result []AllocGroup

	for allocI, ae := range pr.Allocs {
		inc := pr.Entries[ae.Idx].AllocInc
		prev := "(start)"
		if ae.PrevIdx >= 0 {
			prev = Summarize(pr.Entries[ae.PrevIdx])
		}
		next := "(end)"
		if ae.NextIdx >= 0 {
			next = Summarize(pr.Entries[ae.NextIdx])
		}

		k := groupKey{prev, next}
		gi := findGroup(k)
		if gi < 0 {
			gi = len(result)
			seen = append(seen, k)
			groupIdx = append(groupIdx, gi)
			_ = keyOrder
			result = append(result, AllocGroup{
				Key:    prev + " → " + next,
				MinInc: inc,
				MaxInc: inc,
			})
		}

		g := &result[gi]
		g.Count++
		g.TotalBytes += inc
		if inc < g.MinInc {
			g.MinInc = inc
		}
		if inc > g.MaxInc {
			g.MaxInc = inc
		}
		g.Indices = append(g.Indices, allocI)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalBytes > result[j].TotalBytes
	})
	return result
}

// IncHistogram returns a distribution of inc values, sorted by TotalBytes descending.
func IncHistogram(pr ParseResult) []IncBucket {
	// Use a sorted slice of known inc values + linear scan.
	var buckets []IncBucket

	findBucket := func(inc int64) int {
		for i := range buckets {
			if buckets[i].Inc == inc {
				return i
			}
		}
		return -1
	}

	for _, ae := range pr.Allocs {
		inc := pr.Entries[ae.Idx].AllocInc
		bi := findBucket(inc)
		if bi < 0 {
			bi = len(buckets)
			buckets = append(buckets, IncBucket{Inc: inc})
		}
		buckets[bi].Count++
		buckets[bi].TotalBytes += inc
	}

	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].TotalBytes > buckets[j].TotalBytes
	})
	return buckets
}

// GroupByNextMsg groups allocations by the log message that detected them
// (the next non-alloc entry after the [ALLOC] line).
func GroupByNextMsg(pr ParseResult) []AllocGroup {
	var result []AllocGroup

	findGroup := func(key string) int {
		for i := range result {
			if result[i].Key == key {
				return i
			}
		}
		return -1
	}

	for allocI, ae := range pr.Allocs {
		inc := pr.Entries[ae.Idx].AllocInc
		key := "(end)"
		if ae.NextIdx >= 0 {
			key = Summarize(pr.Entries[ae.NextIdx])
		}

		gi := findGroup(key)
		if gi < 0 {
			gi = len(result)
			result = append(result, AllocGroup{
				Key:    key,
				MinInc: inc,
				MaxInc: inc,
			})
		}

		g := &result[gi]
		g.Count++
		g.TotalBytes += inc
		if inc < g.MinInc {
			g.MinInc = inc
		}
		if inc > g.MaxInc {
			g.MaxInc = inc
		}
		g.Indices = append(g.Indices, allocI)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalBytes > result[j].TotalBytes
	})
	return result
}

// PhaseBreakdown returns allocation stats per phase in sequence order.
func PhaseBreakdown(pr ParseResult) []PhaseStat {
	phaseOrder := []string{"init", "dhcp", "post-dhcp", "dns", "post-dns", "ntp", "post-ntp", "listen-idle", "http-serving"}

	stats := make([]PhaseStat, len(phaseOrder))
	for i, p := range phaseOrder {
		stats[i].Phase = p
	}

	findPhase := func(p string) int {
		for i, s := range phaseOrder {
			if s == p {
				return i
			}
		}
		return -1
	}

	for _, ae := range pr.Allocs {
		inc := pr.Entries[ae.Idx].AllocInc
		pi := findPhase(ae.Phase)
		if pi < 0 {
			continue
		}
		stats[pi].Count++
		stats[pi].TotalBytes += inc
	}

	// Filter out phases with no allocations.
	var result []PhaseStat
	for _, s := range stats {
		if s.Count > 0 {
			result = append(result, s)
		}
	}
	return result
}

// TimeSeries buckets allocations into time windows of bucketSec seconds.
func TimeSeries(pr ParseResult, bucketSec float64) []TimeBucket {
	if len(pr.Allocs) == 0 || bucketSec <= 0 {
		return nil
	}

	// Find time range.
	var minT, maxT float64
	first := true
	for _, ae := range pr.Allocs {
		if ae.BootTime <= 0 {
			continue
		}
		if first {
			minT = ae.BootTime
			maxT = ae.BootTime
			first = false
		}
		if ae.BootTime < minT {
			minT = ae.BootTime
		}
		if ae.BootTime > maxT {
			maxT = ae.BootTime
		}
	}

	if maxT <= minT {
		return nil
	}

	nBuckets := int((maxT-minT)/bucketSec) + 1
	buckets := make([]TimeBucket, nBuckets)
	for i := range buckets {
		buckets[i].StartSec = minT + float64(i)*bucketSec
		buckets[i].EndSec = buckets[i].StartSec + bucketSec
	}

	for _, ae := range pr.Allocs {
		if ae.BootTime <= 0 {
			continue
		}
		bi := int((ae.BootTime - minT) / bucketSec)
		if bi < 0 {
			bi = 0
		}
		if bi >= len(buckets) {
			bi = len(buckets) - 1
		}
		inc := pr.Entries[ae.Idx].AllocInc
		buckets[bi].TotalBytes += inc
		buckets[bi].Count++
	}

	return buckets
}
