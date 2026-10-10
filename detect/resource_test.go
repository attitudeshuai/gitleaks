package detect

import (
	"context"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const nogitPath = "../testdata/repos/nogit"

// loadConfig loads a config by name from testdata/config, mirroring the
// existing test setup.
func loadConfig(t *testing.T, cfgName string) config.Config {
	t.Helper()
	t.Cleanup(viper.Reset)

	viper.AddConfigPath(configPath)
	viper.SetConfigName(cfgName)
	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadInConfig())

	var vc config.ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))

	cfg, err := vc.Translate()
	require.NoError(t, err)
	return cfg
}

func scanDirectory(t *testing.T, cfg config.Config) ([]report.Finding, error) {
	detector := NewDetector(cfg)
	return detector.DetectSource(
		context.Background(),
		&sources.Files{
			Config:          &cfg,
			Path:            nogitPath,
			Scheduler:       detector.Scheduler,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		},
	)
}

// TestConcurrencyDoesNotChangeResults verifies that the same input under the
// same configuration produces the same findings (count and content) whether
// it is scanned with the default worker count, a single worker, or a small
// worker pool.
func TestConcurrencyDoesNotChangeResults(t *testing.T) {
	workerCounts := []int{1, 2, 4, 40}

	var baseline []report.Finding
	for _, workers := range workerCounts {
		cfg := loadConfig(t, "simple")
		cfg.Concurrency.Workers = workers
		cfg.Concurrency.MaxInFlight = workers

		findings, err := scanDirectory(t, cfg)
		require.NoError(t, err)

		if baseline == nil {
			baseline = findings
			require.NotEmpty(t, baseline)
			continue
		}
		assert.ElementsMatch(t, baseline, findings)
	}
}

// TestSingleWorkerStillCompletes verifies that a worker budget of 1 still
// completes the full scan correctly, just serially.
func TestSingleWorkerStillCompletes(t *testing.T) {
	cfg := loadConfig(t, "simple")
	cfg.Concurrency.Workers = 1
	cfg.Concurrency.MaxInFlight = 1

	findings, err := scanDirectory(t, cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, findings)
}

// expandingSource is a deterministic test source: it dispatches a single
// target whose reported memory grows past the budget (mimicking decoding
// expansion) while the target is processed, then yields a fragment with a
// finding.
type expandingSource struct {
	scheduler *sources.Scheduler
	raw       string
}

func (s *expandingSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	err := s.scheduler.Go(ctx, "expanding-target", 40, func(taskCtx context.Context) error {
		// Report growth past the budget while the target is in flight.
		sources.TargetFromContext(taskCtx).Grow(60)
		return yield(taskCtx, sources.Fragment{Raw: s.raw}, nil)
	})
	if err != nil {
		return err
	}
	// Wait for the dispatched target to finish, like the built-in sources do.
	s.scheduler.Wait()
	return nil
}

// TestMemoryBudgetFail verifies that, under the fail policy, a scan that
// exceeds the memory budget ends with an error after in-flight targets finish,
// while findings produced by already started targets are still returned.
func TestMemoryBudgetFail(t *testing.T) {
	cfg := loadConfig(t, "simple")
	cfg.Resources.MemoryBytes = 80 // est 40 fits, est+growth 100 exceeds
	cfg.Resources.OnExhausted = config.OnExhaustedFail

	detector := NewDetector(cfg)
	source := &expandingSource{
		scheduler: detector.Scheduler,
		raw:       `awsToken: "AKIALALEMEL33243OLIA"`,
	}
	findings, err := detector.DetectSource(context.Background(), source)

	require.Error(t, err)
	assert.ErrorIs(t, err, sources.ErrMemoryBudget)
	assert.True(t, detector.MemoryBudgetExhausted())
	assert.Len(t, findings, 1, "findings produced by the started target are retained")
	assert.Equal(t, "aws-access-key", findings[0].RuleID)
}

// TestMemoryBudgetPartial verifies that, under the partial policy, the scan
// ends without an error while retaining the findings from dispatched targets,
// and that the truncation is still honestly reported.
func TestMemoryBudgetPartial(t *testing.T) {
	cfg := loadConfig(t, "simple")

	// A 1-byte budget admits nothing: all non-empty targets exceed it.
	cfg.Resources.MemoryBytes = 1
	cfg.Resources.OnExhausted = config.OnExhaustedPartial

	detector := NewDetector(cfg)
	findings, err := detector.DetectSource(
		context.Background(),
		&sources.Files{
			Config:          &cfg,
			Path:            nogitPath,
			Scheduler:       detector.Scheduler,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		},
	)

	require.NoError(t, err, "partial policy does not fail the scan")
	assert.True(t, detector.MemoryBudgetExhausted())
	assert.Equal(t, int64(0), detector.Scheduler.Dispatched())
	assert.GreaterOrEqual(t, detector.TargetsNotDispatched(), int64(2))
	assert.Empty(t, findings)
}

// TestMaxFindingsLimit verifies that, once the finding cap is reached, new
// findings are not retained and the truncation is counted and reported.
func TestMaxFindingsLimit(t *testing.T) {
	// Establish the uncapped result set.
	baseCfg := loadConfig(t, "simple")
	baseline, err := scanDirectory(t, baseCfg)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(baseline), 2, "fixture must produce multiple findings")

	cfg := loadConfig(t, "simple")
	cfg.Resources.MaxFindings = 1

	detector := NewDetector(cfg)
	findings, err := detector.DetectSource(
		context.Background(),
		&sources.Files{
			Config:          &cfg,
			Path:            nogitPath,
			Scheduler:       detector.Scheduler,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		},
	)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, len(baseline)-1, detector.FindingsTruncated())
	assert.Contains(t, baseline, findings[0], "the retained finding was part of the full result")
}
