package report

import (
	"sort"
	"time"

	toolversion "github.com/zricethezav/gitleaks/v8/version"
)

const (
	// ToolName is the canonical tool identity reported in scan summaries.
	ToolName = driver

	// VersionPlaceholder is the explicit tool version used when the
	// build-injected version cannot be read. It deliberately differs from
	// the legacy hard-coded SARIF constant.
	VersionPlaceholder = "dev"

	// DefaultConfigIdentity is the explicit config identity used when no
	// config file is specified and the embedded default config is in use.
	DefaultConfigIdentity = "builtin://default"

	// EnvConfigIdentity is the config identity used when the config is
	// provided via the GITLEAKS_CONFIG_TOML environment variable.
	EnvConfigIdentity = "env://GITLEAKS_CONFIG_TOML"
)

// Supported scan source types.
const (
	SourceTypeGit       = "git"
	SourceTypeDirectory = "directory"
	SourceTypeStdin     = "stdin"
)

// Supported group dimensions.
const (
	GroupByRule = "rule"
	GroupByTag  = "tag"
	GroupByFile = "file"
)

// ScanSummary is the scan-level companion to the findings list. It captures
// the scale of the scan, how the hits are distributed, and where the scan
// came from. The same instance is rendered into every report format, so all
// formats report identical numbers.
type ScanSummary struct {
	// Tool is the identity and version of the tool that produced the scan.
	Tool ToolInfo `json:"tool"`

	// Config identifies the configuration used for the scan.
	Config ConfigInfo `json:"config"`

	// Source describes what was scanned.
	Source SourceInfo `json:"source"`

	// GeneratedAt is the time the summary was produced.
	GeneratedAt time.Time `json:"generatedAt"`

	// FindingsCount is the total number of findings in the report.
	FindingsCount int `json:"findingsCount"`

	// BytesScanned is the number of bytes inspected during the scan.
	BytesScanned uint64 `json:"bytesScanned"`

	// CommitsScanned is the number of unique commits inspected during the
	// scan. It is 0 for non-git sources.
	CommitsScanned int `json:"commitsScanned"`

	// Groups holds optional hit counts grouped by rule, tag and file.
	Groups GroupSet `json:"groups"`
}

// ToolInfo identifies the tool and its version.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ConfigInfo identifies the configuration used for the scan.
type ConfigInfo struct {
	// Identity is the config file path, or an explicit non-file identity
	// such as DefaultConfigIdentity or EnvConfigIdentity.
	Identity string `json:"identity"`
}

// SourceInfo describes the scan target.
type SourceInfo struct {
	// Type is one of SourceTypeGit, SourceTypeDirectory, SourceTypeStdin.
	Type string `json:"type"`
	// Path is the path of the scan target, if any.
	Path string `json:"path"`
}

// GroupSet contains the requested hit-count groupings.
type GroupSet struct {
	ByRule *GroupCounts `json:"byRule,omitempty"`
	ByTag  *GroupCounts `json:"byTag,omitempty"`
	ByFile *GroupCounts `json:"byFile,omitempty"`
}

// GroupCounts is a single grouping of hit counts.
type GroupCounts struct {
	// Counts are ordered deterministically (count desc, key asc).
	Counts []GroupCount `json:"counts"`

	// Total is the number of distinct keys in the full grouping before any
	// truncation. It equals len(Counts) when Limited is false.
	Total int `json:"total"`

	// Limited reports that Counts were truncated to GroupLimit. It must
	// never be silently true: consumers can see entries were dropped.
	Limited bool `json:"limited,omitempty"`
}

// GroupCount is a key/count pair in a grouping.
type GroupCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// SummaryOptions configures which groupings are produced and whether they
// are truncated.
type SummaryOptions struct {
	ByRule bool
	ByTag  bool
	ByFile bool

	// GroupLimit caps the number of entries kept in each grouping.
	// 0 means no limit.
	GroupLimit int
}

// ScanMeta is the scan-level input collected while running a scan.
type ScanMeta struct {
	// Version is the build-injected tool version.
	Version string

	// ConfigIdentity identifies the config used for the scan.
	ConfigIdentity string

	// SourceType is the kind of source scanned.
	SourceType string

	// SourcePath is the path of the scan target, if any.
	SourcePath string

	// BytesScanned is the number of bytes inspected during the scan.
	BytesScanned uint64

	// CommitsScanned is the number of unique commits inspected.
	CommitsScanned int
}

// NewScanSummary builds a ScanSummary from the finalized findings and scan
// metadata. It is called once after the scan completes, using the same
// findings slice written to the report, so the counts can neither be lost
// nor double-counted under concurrent scanning.
func NewScanSummary(meta ScanMeta, findings []Finding, opts SummaryOptions) *ScanSummary {
	summary := &ScanSummary{
		Tool: ToolInfo{
			Name:    ToolName,
			Version: ResolveVersion(meta.Version),
		},
		Config: ConfigInfo{
			Identity: meta.ConfigIdentity,
		},
		Source: SourceInfo{
			Type: meta.SourceType,
			Path: meta.SourcePath,
		},
		GeneratedAt:    time.Now().UTC(),
		FindingsCount:  len(findings),
		BytesScanned:   meta.BytesScanned,
		CommitsScanned: meta.CommitsScanned,
	}
	if summary.Config.Identity == "" {
		summary.Config.Identity = DefaultConfigIdentity
	}

	if opts.ByRule {
		counts := make(map[string]int)
		for _, f := range findings {
			counts[f.RuleID]++
		}
		summary.Groups.ByRule = newGroupCounts(counts, opts.GroupLimit)
	}
	if opts.ByTag {
		counts := make(map[string]int)
		for _, f := range findings {
			for _, tag := range f.Tags {
				counts[tag]++
			}
		}
		summary.Groups.ByTag = newGroupCounts(counts, opts.GroupLimit)
	}
	if opts.ByFile {
		counts := make(map[string]int)
		for _, f := range findings {
			counts[FindingPath(f)]++
		}
		summary.Groups.ByFile = newGroupCounts(counts, opts.GroupLimit)
	}

	return summary
}

// ResolveVersion returns the build-injected version, falling back to an
// explicit placeholder when the version was not injected at build time.
func ResolveVersion(injected string) string {
	if injected == "" || injected == toolversion.DefaultMsg {
		return VersionPlaceholder
	}
	return injected
}

// FindingPath returns the single path field that identifies where a finding
// lives in the report: the symlink path when one was followed, otherwise the
// (possibly archive-internal) file path. Archive-internal paths and symlink
// paths therefore use the same key here as they do in report locations.
func FindingPath(f Finding) string {
	if f.SymlinkFile != "" {
		return f.SymlinkFile
	}
	return f.File
}

// newGroupCounts turns a key/count map into a deterministic GroupCounts,
// applying a truncation limit when one is configured.
func newGroupCounts(counts map[string]int, limit int) *GroupCounts {
	gc := &GroupCounts{
		Counts: make([]GroupCount, 0, len(counts)),
		Total:  len(counts),
	}

	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})

	if limit > 0 && len(keys) > limit {
		gc.Limited = true
		keys = keys[:limit]
	}

	for _, key := range keys {
		gc.Counts = append(gc.Counts, GroupCount{Key: key, Count: counts[key]})
	}
	return gc
}

// SummarySettings is embedded by reporters that can render a ScanSummary.
type SummarySettings struct {
	Summary *ScanSummary
}

// ScanSummarySetter is implemented by reporters that accept a scan summary.
type ScanSummarySetter interface {
	SetScanSummary(summary *ScanSummary)
}

// SetScanSummary attaches a scan summary to the reporter.
func (s *SummarySettings) SetScanSummary(summary *ScanSummary) {
	s.Summary = summary
}
