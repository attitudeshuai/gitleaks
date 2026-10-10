package detect

import (
	"context"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// assertOrdered verifies that findings are in the deterministic output
// order, allowing ties on identical keys.
func assertOrdered(t *testing.T, findings []report.Finding) {
	t.Helper()
	for i := 1; i < len(findings); i++ {
		assert.False(t, report.Less(findings[i], findings[i-1]),
			"findings out of order at index %d: %q before %q", i, findings[i].File, findings[i-1].File)
	}
}

func TestFinalizeFindingsOrder(t *testing.T) {
	d := NewDetector(config.Config{})

	d.AddFinding(report.Finding{RuleID: "c2", Commit: "c2", CommitOrder: 2, File: "z.go", StartLine: 1, EndLine: 1})
	d.AddFinding(report.Finding{RuleID: "c1-b", Commit: "c1", CommitOrder: 1, File: "b.go", StartLine: 2, EndLine: 2})
	d.AddFinding(report.Finding{RuleID: "c1-a-r2", Commit: "c1", CommitOrder: 1, File: "a.go", StartLine: 1, EndLine: 1})
	d.AddFinding(report.Finding{RuleID: "c1-a-r1", Commit: "c1", CommitOrder: 1, File: "a.go", StartLine: 1, EndLine: 1})
	d.AddFinding(report.Finding{RuleID: "nocommit", File: "n.go", StartLine: 1, EndLine: 1})

	d.finalizeFindings()

	assert.Equal(t, []string{"c1-a-r1", "c1-a-r2", "c1-b", "c2", "nocommit"},
		func() []string {
			ids := make([]string, len(d.findings))
			for i, f := range d.findings {
				ids[i] = f.RuleID
			}
			return ids
		}())
}

func TestFinalizeFindingsNoSort(t *testing.T) {
	d := NewDetector(config.Config{})
	d.NoSort = true

	d.AddFinding(report.Finding{RuleID: "first", Commit: "c", CommitOrder: 2, File: "z.go", StartLine: 9})
	d.AddFinding(report.Finding{RuleID: "second", Commit: "c", CommitOrder: 1, File: "a.go", StartLine: 1})

	// Collection order is preserved exactly.
	d.finalizeFindings()
	require.Len(t, d.findings, 2)
	assert.Equal(t, "first", d.findings[0].RuleID)
	assert.Equal(t, "second", d.findings[1].RuleID)
}

func TestCommitOrderPropagation(t *testing.T) {
	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test-rule": {
				RuleID: "test-rule",
				Regex:  regexp.MustCompile(`token=\w+`),
			},
		},
	}
	d := NewDetector(cfg)

	findings := d.Detect(Fragment{
		Raw:         "token=abc123\n",
		CommitSHA:   "c",
		CommitOrder: 7,
	})

	require.Len(t, findings, 1)
	assert.Equal(t, 7, findings[0].CommitOrder)
	assert.Equal(t, "c", findings[0].Commit)
}

func newConfiguredDetector(t *testing.T, cfgName string) (*Detector, config.Config) {
	t.Helper()
	viper.Reset()
	viper.AddConfigPath(configPath)
	viper.SetConfigName(cfgName)
	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadInConfig())

	var vc config.ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)

	return NewDetector(cfg), cfg
}

// TestDirectorySourceOrdering runs the same directory scan twice and
// requires identical ordered output regardless of scheduling.
func TestDirectorySourceOrdering(t *testing.T) {
	scan := func() []report.Finding {
		d, cfg := newConfiguredDetector(t, "generic")
		findings, err := d.DetectSource(context.Background(), &sources.Files{
			Config: &cfg,
			Path:   repoBasePath + "nogit",
			Sema:   d.Sema,
		})
		require.NoError(t, err)
		return findings
	}

	first, second := scan(), scan()
	assert.Len(t, first, len(second))
	assert.Equal(t, first, second)
	assertOrdered(t, first)

	// Findings can be reconstructed by file/location: .env.prod before main.go.
	require.NotEmpty(t, first)
	assert.Contains(t, first[0].File, ".env.prod")
}

// TestArchiveSourceOrdering ensures archive inner paths participate in the
// same ordering and remain stable across runs.
func TestArchiveSourceOrdering(t *testing.T) {
	scan := func() []report.Finding {
		d, cfg := newConfiguredDetector(t, "simple")
		findings, err := d.DetectSource(context.Background(), &sources.Files{
			Config:          &cfg,
			Path:            archivesBasePath + "files.zip",
			Sema:            d.Sema,
			MaxArchiveDepth: 1,
		})
		require.NoError(t, err)
		return findings
	}

	first, second := scan(), scan()
	assert.Len(t, first, len(second))
	assert.Equal(t, first, second)
	assertOrdered(t, first)

	// Inner paths sort: api.go before main.go.
	require.NotEmpty(t, first)
	assert.Equal(t, archivesBasePath+"files.zip!files/api.go", first[0].File)
}
