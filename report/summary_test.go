package report

import (
	"encoding/json"
	"testing"

	toolversion "github.com/zricethezav/gitleaks/v8/version"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func summaryFindings() []Finding {
	return []Finding{
		{RuleID: "rule-a", File: "auth.py", Tags: []string{"tag1", "tag2"}},
		{RuleID: "rule-a", File: "auth.py", SymlinkFile: "link/auth.py", Tags: []string{"tag1"}},
		{RuleID: "rule-b", File: "bundle.tar!inner/secret.env", Tags: []string{"tag2", "tag3"}},
	}
}

func allGroupOptions(limit int) SummaryOptions {
	return SummaryOptions{ByRule: true, ByTag: true, ByFile: true, GroupLimit: limit}
}

func TestNewScanSummaryCounts(t *testing.T) {
	findings := summaryFindings()
	summary := NewScanSummary(ScanMeta{
		Version:        "v9.9.9",
		ConfigIdentity: "/etc/gitleaks.toml",
		SourceType:     SourceTypeGit,
		SourcePath:     "/repo",
		BytesScanned:   4242,
		CommitsScanned: 7,
	}, findings, allGroupOptions(0))

	// The headline count equals the findings rendered in the report.
	assert.Equal(t, len(findings), summary.FindingsCount)
	assert.Equal(t, uint64(4242), summary.BytesScanned)
	assert.Equal(t, 7, summary.CommitsScanned)
	assert.Equal(t, "v9.9.9", summary.Tool.Version)
	assert.Equal(t, ToolName, summary.Tool.Name)
	assert.Equal(t, "/etc/gitleaks.toml", summary.Config.Identity)
	assert.Equal(t, SourceTypeGit, summary.Source.Type)
	assert.False(t, summary.GeneratedAt.IsZero())

	// Sum of rule counts equals the number of findings.
	var ruleTotal int
	for _, c := range summary.Groups.ByRule.Counts {
		ruleTotal += c.Count
	}
	assert.Equal(t, len(findings), ruleTotal)

	// Deterministic ordering: highest count first, then key.
	assert.Equal(t, "rule-a", summary.Groups.ByRule.Counts[0].Key)
	assert.Equal(t, 2, summary.Groups.ByRule.Counts[0].Count)
	assert.Equal(t, "rule-b", summary.Groups.ByRule.Counts[1].Key)
	assert.False(t, summary.Groups.ByRule.Limited)
	assert.Equal(t, 2, summary.Groups.ByRule.Total)

	// Tags count each occurrence; a finding with two tags feeds both.
	tagCounts := map[string]int{}
	for _, c := range summary.Groups.ByTag.Counts {
		tagCounts[c.Key] = c.Count
	}
	assert.Equal(t, map[string]int{"tag1": 2, "tag2": 2, "tag3": 1}, tagCounts)

	// File grouping uses the single report path field: a symlink finding
	// is keyed by SymlinkFile, and archive-internal paths are preserved.
	fileCounts := map[string]int{}
	for _, c := range summary.Groups.ByFile.Counts {
		fileCounts[c.Key] = c.Count
	}
	assert.Equal(t, map[string]int{
		"auth.py":                     1,
		"link/auth.py":                1,
		"bundle.tar!inner/secret.env": 1,
	}, fileCounts)

	// File-group counts also total the findings exactly.
	var fileTotal int
	for _, c := range summary.Groups.ByFile.Counts {
		fileTotal += c.Count
	}
	assert.Equal(t, len(findings), fileTotal)
}

func TestScanSummaryGroupTruncation(t *testing.T) {
	summary := NewScanSummary(ScanMeta{Version: "v9.9.9"}, summaryFindings(), allGroupOptions(1))

	for _, gc := range []*GroupCounts{
		summary.Groups.ByRule,
		summary.Groups.ByTag,
		summary.Groups.ByFile,
	} {
		require.NotNil(t, gc)
		assert.Len(t, gc.Counts, 1)
		assert.True(t, gc.Limited, "truncation must be flagged, never silent")
		assert.Greater(t, gc.Total, len(gc.Counts))
	}

	// The kept entry is the most frequent one.
	assert.Equal(t, "rule-a", summary.Groups.ByRule.Counts[0].Key)
}

func TestScanSummaryZeroFindings(t *testing.T) {
	summary := NewScanSummary(ScanMeta{}, []Finding{}, allGroupOptions(0))

	assert.Equal(t, 0, summary.FindingsCount)
	assert.Equal(t, uint64(0), summary.BytesScanned)
	// Non-git / commit-less sources must report an explicit zero, not omit.
	assert.Equal(t, 0, summary.CommitsScanned)
	assert.Empty(t, summary.Source.Type)

	for name, gc := range map[string]*GroupCounts{
		"rule": summary.Groups.ByRule,
		"tag":  summary.Groups.ByTag,
		"file": summary.Groups.ByFile,
	} {
		require.NotNil(t, gc, name)
		assert.NotNil(t, gc.Counts, name)
		assert.Empty(t, gc.Counts, name)
		assert.Equal(t, 0, gc.Total, name)
		assert.False(t, gc.Limited, name)
	}

	// The summary must still serialize to legal JSON with empty arrays.
	data, err := json.Marshal(summary)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	groups := decoded["groups"].(map[string]any)
	for _, key := range []string{"byRule", "byTag", "byFile"} {
		g := groups[key].(map[string]any)
		assert.Equal(t, []any{}, g["counts"], key)
	}
}

func TestScanSummaryVersionAndConfigPlaceholders(t *testing.T) {
	for _, injected := range []string{"", toolversion.DefaultMsg} {
		summary := NewScanSummary(ScanMeta{Version: injected}, nil, SummaryOptions{})
		assert.Equal(t, VersionPlaceholder, summary.Tool.Version)
	}

	summary := NewScanSummary(ScanMeta{Version: "v8.30.0"}, nil, SummaryOptions{})
	assert.Equal(t, "v8.30.0", summary.Tool.Version)

	// Empty config identity resolves to the built-in default identity.
	assert.Equal(t, DefaultConfigIdentity, summary.Config.Identity)
}

func TestScanSummaryDeterministic(t *testing.T) {
	findings := summaryFindings()
	first := NewScanSummary(ScanMeta{Version: "v9.9.9"}, findings, allGroupOptions(0))
	second := NewScanSummary(ScanMeta{Version: "v9.9.9"}, findings, allGroupOptions(0))

	// Same input must produce the same counts and grouping every run.
	assert.Equal(t, first.FindingsCount, second.FindingsCount)
	assert.Equal(t, first.Groups, second.Groups)
}

func TestFindingPath(t *testing.T) {
	assert.Equal(t, "a/b.py", FindingPath(Finding{File: "a/b.py"}))
	assert.Equal(t, "link.py", FindingPath(Finding{File: "a/b.py", SymlinkFile: "link.py"}))
	assert.Equal(t, "a.tar!x.env", FindingPath(Finding{File: "a.tar!x.env"}))
}
