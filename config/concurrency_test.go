package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCapacity(t *testing.T) {
	tests := map[string]struct {
		input string
		want  int64
	}{
		"bare bytes":       {input: "1024", want: 1024},
		"bytes unit":       {input: "100B", want: 100},
		"kilobytes":        {input: "1KB", want: 1_000},
		"megabytes":        {input: "2MB", want: 2_000_000},
		"gigabytes":        {input: "1GB", want: 1_000_000_000},
		"kibibytes":        {input: "1KiB", want: 1024},
		"mebibytes":        {input: "1MiB", want: 1024 * 1024},
		"gibibytes":        {input: "2GiB", want: 2 * 1024 * 1024 * 1024},
		"lowercase unit":   {input: "1kb", want: 1_000},
		"whitespace":       {input: "  5 MB ", want: 5_000_000},
		"fractional value": {input: "1.5KB", want: 1_500},
		"single letters":   {input: "1k", want: 1_000},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseCapacity(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseCapacityInvalid(t *testing.T) {
	for _, input := range []string{
		"",
		"   ",
		"-1MB",
		"0",
		"0B",
		"abc",
		"100XB",
		"100 megawatts",
		"MB",
	} {
		t.Run(input, func(t *testing.T) {
			_, err := ParseCapacity(input)
			require.Error(t, err, "expected error for %q", input)
		})
	}
}

// translateInline parses an inline TOML config and returns the translated
// Config.
func translateInline(t *testing.T, tomlContent string) Config {
	t.Helper()
	t.Cleanup(viper.Reset)

	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(tomlContent)))

	var vc ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))

	cfg, err := vc.Translate()
	require.NoError(t, err)
	return cfg
}

// translateInlineError parses an inline TOML config and asserts that
// translation fails.
func translateInlineError(t *testing.T, tomlContent string, wantErr string) {
	t.Helper()
	t.Cleanup(viper.Reset)

	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(tomlContent)))

	var vc ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))

	_, err := vc.Translate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), wantErr)
}

func TestTranslateLimitsDefaults(t *testing.T) {
	// No sections: historical defaults.
	cfg := translateInline(t, "title = \"test\"")
	assert.Equal(t, DefaultWorkers, cfg.Concurrency.Workers)
	assert.Equal(t, DefaultWorkers, cfg.Concurrency.MaxInFlight)
	assert.Equal(t, int64(0), cfg.Resources.MemoryBytes)
	assert.Equal(t, 0, cfg.Resources.MaxFindings)
	assert.Equal(t, OnExhaustedFail, cfg.Resources.OnExhausted)
}

func TestTranslateLimitsValid(t *testing.T) {
	cfg := translateInline(t, `
[concurrency]
workers = 4
max_in_flight = 8

[resources]
memory = "256MB"
max_findings = 10
on_exhausted = "partial"
`)
	assert.Equal(t, 4, cfg.Concurrency.Workers)
	assert.Equal(t, 8, cfg.Concurrency.MaxInFlight)
	assert.Equal(t, int64(256_000_000), cfg.Resources.MemoryBytes)
	assert.Equal(t, 10, cfg.Resources.MaxFindings)
	assert.Equal(t, OnExhaustedPartial, cfg.Resources.OnExhausted)
}

func TestTranslateLimitsMaxInFlightDefaultsToWorkers(t *testing.T) {
	cfg := translateInline(t, `
[concurrency]
workers = 7
`)
	assert.Equal(t, 7, cfg.Concurrency.Workers)
	assert.Equal(t, 7, cfg.Concurrency.MaxInFlight)
}

func TestTranslateLimitsInvalid(t *testing.T) {
	tests := map[string]struct {
		config  string
		wantErr string
	}{
		"zero workers": {
			config:  "[concurrency]\nworkers = 0",
			wantErr: "[concurrency] |workers| must be greater than 0",
		},
		"negative workers": {
			config:  "[concurrency]\nworkers = -2",
			wantErr: "[concurrency] |workers| must be greater than 0",
		},
		"zero max_in_flight": {
			config:  "[concurrency]\nmax_in_flight = 0",
			wantErr: "[concurrency] |max_in_flight| must be greater than 0",
		},
		"negative max_in_flight": {
			config:  "[concurrency]\nmax_in_flight = -1",
			wantErr: "[concurrency] |max_in_flight| must be greater than 0",
		},
		"zero max_findings": {
			config:  "[resources]\nmax_findings = 0",
			wantErr: "[resources] |max_findings| must be greater than 0",
		},
		"negative max_findings": {
			config:  "[resources]\nmax_findings = -5",
			wantErr: "[resources] |max_findings| must be greater than 0",
		},
		"bad memory unit": {
			config:  "[resources]\nmemory = \"500XB\"",
			wantErr: "[resources] |memory|",
		},
		"zero memory": {
			config:  "[resources]\nmemory = \"0\"",
			wantErr: "[resources] |memory|",
		},
		"negative memory": {
			config:  "[resources]\nmemory = \"-1MB\"",
			wantErr: "[resources] |memory|",
		},
		"bad on_exhausted": {
			config:  "[resources]\non_exhausted = \"give-up\"",
			wantErr: "[resources] |on_exhausted|",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			translateInlineError(t, tt.config, tt.wantErr)
		})
	}
}
