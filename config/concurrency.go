package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

// DefaultWorkers is the number of targets processed concurrently when no
// concurrency.workers value is configured. It preserves the historical
// behavior of gitleaks.
const DefaultWorkers = 40

// Concurrency configures how many targets are dispatched and processed
// concurrently during a scan.
type Concurrency struct {
	// Workers is the maximum number of targets processed at the same time.
	Workers int

	// MaxInFlight is the maximum number of dispatched-but-unfinished targets,
	// including targets that have been admitted but are waiting for a worker
	// slot.
	MaxInFlight int
}

// OnExhaustedAction determines what happens after the memory budget is
// exhausted and all in-flight targets have finished.
type OnExhaustedAction string

const (
	// OnExhaustedFail ends the scan with an error.
	OnExhaustedFail OnExhaustedAction = "fail"
	// OnExhaustedPartial ends the scan without an error, retaining partial
	// results.
	OnExhaustedPartial OnExhaustedAction = "partial"
)

// Resources configures the resource budgets of a scan.
type Resources struct {
	// MemoryBytes is the estimated memory, in bytes, that in-flight targets
	// are allowed to occupy. The estimate covers the targets' raw content as
	// well as growth from decoding. A value of 0 disables the budget.
	MemoryBytes int64

	// MaxFindings is the maximum number of findings retained by the scan.
	// A value of 0 disables the limit.
	MaxFindings int

	// OnExhausted decides whether memory-budget exhaustion fails the scan or
	// ends it with partial results.
	OnExhausted OnExhaustedAction
}

// viperConcurrency is the intermediary struct used to parse the
// [concurrency] config section. Pointers are used so that an omitted value
// can be distinguished from an explicit zero, which is invalid.
type viperConcurrency struct {
	Workers     *int
	MaxInFlight *int `mapstructure:"max_in_flight"`
}

// viperResources is the intermediary struct used to parse the [resources]
// config section.
type viperResources struct {
	Memory      string
	MaxFindings *int `mapstructure:"max_findings"`
	OnExhausted string `mapstructure:"on_exhausted"`
}

// translateLimits parses and validates the [concurrency] and [resources]
// sections. These are top-level, operational settings; they are only read
// from the root config, never from extended configs.
func (vc *ViperConfig) translateLimits() (Concurrency, Resources, error) {
	c := Concurrency{}

	if vc.Concurrency.Workers != nil {
		workers := *vc.Concurrency.Workers
		if workers <= 0 {
			return c, Resources{}, fmt.Errorf(
				"[concurrency] |workers| must be greater than 0, got %d", workers)
		}
		c.Workers = workers
	} else {
		c.Workers = DefaultWorkers
	}

	if vc.Concurrency.MaxInFlight != nil {
		maxInFlight := *vc.Concurrency.MaxInFlight
		if maxInFlight <= 0 {
			return c, Resources{}, fmt.Errorf(
				"[concurrency] |max_in_flight| must be greater than 0, got %d", maxInFlight)
		}
		c.MaxInFlight = maxInFlight
	} else {
		// Defaulting to the worker count reproduces the historical behavior:
		// dispatch blocks while every worker slot is occupied.
		c.MaxInFlight = c.Workers
	}

	r := Resources{OnExhausted: OnExhaustedFail}

	switch action := strings.ToLower(strings.TrimSpace(vc.Resources.OnExhausted)); action {
	case "", string(OnExhaustedFail):
		r.OnExhausted = OnExhaustedFail
	case string(OnExhaustedPartial):
		r.OnExhausted = OnExhaustedPartial
	default:
		return c, Resources{}, fmt.Errorf(
			"[resources] |on_exhausted| must be %q or %q, got %q",
			OnExhaustedFail, OnExhaustedPartial, vc.Resources.OnExhausted)
	}

	if memory := strings.TrimSpace(vc.Resources.Memory); memory != "" {
		memoryBytes, err := ParseCapacity(memory)
		if err != nil {
			return c, Resources{}, fmt.Errorf("[resources] |memory| %w", err)
		}
		r.MemoryBytes = memoryBytes
	}

	if vc.Resources.MaxFindings != nil {
		maxFindings := *vc.Resources.MaxFindings
		if maxFindings <= 0 {
			return c, Resources{}, fmt.Errorf(
				"[resources] |max_findings| must be greater than 0, got %d", maxFindings)
		}
		r.MaxFindings = maxFindings
	}

	return c, r, nil
}

var capacityPattern = regexp.MustCompile(`^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*$`)

// capacityMultipliers maps accepted capacity units to their size in bytes.
// Decimal units use powers of 1000, binary units (KiB, MiB, GiB) use powers
// of 1024.
var capacityMultipliers = map[string]float64{
	"":    1,
	"b":   1,
	"k":   1_000,
	"kb":  1_000,
	"m":   1_000_000,
	"mb":  1_000_000,
	"g":   1_000_000_000,
	"gb":  1_000_000_000,
	"kib": 1024,
	"mib": 1024 * 1024,
	"gib": 1024 * 1024 * 1024,
}

// ParseCapacity parses a human-readable capacity value such as "100MB",
// "1.5GiB" or "1024" (bytes) into a number of bytes. Negative, zero and
// unparseable values (including unknown units) are rejected.
func ParseCapacity(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("capacity is empty")
	}

	m := capacityPattern.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf(
			"could not parse %q: expected a positive number with an optional unit (B, KB, MB, GB, KiB, MiB, GiB)",
			s)
	}

	value, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("could not parse %q: %w", s, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("capacity must be greater than 0, got %s", s)
	}

	multiplier, ok := capacityMultipliers[strings.ToLower(m[2])]
	if !ok {
		return 0, fmt.Errorf("could not parse %q: unknown unit %q", s, m[2])
	}

	bytes := int64(value * multiplier)
	if bytes <= 0 {
		return 0, fmt.Errorf("capacity must be greater than 0, got %s", s)
	}
	return bytes, nil
}
