package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	require.NoError(t, err)
	return n
}

func testFindings() []Finding {
	return []Finding{
		{
			RuleID: "test-rule",
			Match:  "line containing secret",
			Secret: "a secret",
			File:   "auth.py",
			Commit: "0000000000000000",
			Tags:   []string{"tag1", "tag2"},
		},
		{
			RuleID: "other-rule",
			Secret: "another secret",
			File:   "auth.py",
			Tags:   []string{"tag1"},
		},
	}
}

func testSummary() (*ScanSummary, []Finding) {
	findings := testFindings()
	return NewScanSummary(ScanMeta{
		Version:        "v9.9.9",
		ConfigIdentity: DefaultConfigIdentity,
		SourceType:     SourceTypeGit,
		SourcePath:     "/repo",
		BytesScanned:   1000,
		CommitsScanned: 3,
	}, findings, SummaryOptions{ByRule: true, ByTag: true, ByFile: true}), findings
}

func writeReport(t *testing.T, reporter Reporter, findings []Finding, summary *ScanSummary) string {
	t.Helper()
	if summary != nil {
		setter, ok := reporter.(ScanSummarySetter)
		require.True(t, ok)
		setter.SetScanSummary(summary)
	}

	buf := testWriter{bytes.NewBuffer(nil)}
	require.NoError(t, reporter.Write(buf, findings))
	return buf.String()
}

func TestJSONWithSummary(t *testing.T) {
	summary, findings := testSummary()
	out := writeReport(t, &JsonReporter{}, findings, summary)

	// With a summary the report is an object, not a bare array.
	assert.Equal(t, "{", strings.TrimSpace(out)[:1])

	var envelope struct {
		Summary  *ScanSummary `json:"summary"`
		Findings []Finding    `json:"findings"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &envelope))
	require.NotNil(t, envelope.Summary)
	assert.Len(t, envelope.Findings, 2)
	assert.Equal(t, 2, envelope.Summary.FindingsCount)

	// Rule-group totals reconcile with the findings list.
	var total int
	for _, c := range envelope.Summary.Groups.ByRule.Counts {
		total += c.Count
	}
	assert.Equal(t, len(envelope.Findings), total)
}

func TestJSONWithSummaryZeroFindings(t *testing.T) {
	summary := NewScanSummary(ScanMeta{Version: "v9.9.9"}, []Finding{}, SummaryOptions{ByRule: true})
	out := writeReport(t, &JsonReporter{}, []Finding{}, summary)
	var envelope struct {
		Summary  *ScanSummary `json:"summary"`
		Findings []Finding    `json:"findings"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &envelope))
	assert.Equal(t, 0, envelope.Summary.FindingsCount)
	assert.NotNil(t, envelope.Findings)
	assert.Empty(t, envelope.Findings)
}

func TestCSVWithSummary(t *testing.T) {
	summary, _ := testSummary()
	findings := []Finding{
		{
			RuleID:      "test-rule",
			Secret:      "a secret",
			Match:       "line containing secret",
			File:        "auth.py",
			Fingerprint: "fingerprint",
			Tags:        []string{"tag1", "tag2", "tag3"},
		},
	}
	summary = NewScanSummary(ScanMeta{Version: "v9.9.9"}, findings,
		SummaryOptions{ByRule: true, ByTag: true, ByFile: true})
	out := writeReport(t, &CsvReporter{}, findings, summary)

	reader := csv.NewReader(strings.NewReader(out))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	require.NoError(t, err)

	// Header and finding rows keep the exact existing columns.
	assert.Equal(t, []string{
		"RuleID", "Commit", "File", "SymlinkFile", "Secret", "Match",
		"StartLine", "EndLine", "StartColumn", "EndColumn", "Author",
		"Message", "Date", "Email", "Fingerprint", "Tags",
	}, records[0])
	assert.Equal(t, "test-rule", records[1][0])
	require.Equal(t, len(records[0]), len(records[1]))

	// Every summary record keeps the same arity and uses the marker scheme.
	var (
		sawMarker  bool
		sawMeta    bool
		sawRule    bool
		sawTag     bool
		sawFile    bool
		groupTotal int
	)
	for _, rec := range records[2:] {
		require.Len(t, rec, len(records[0]))
		switch {
		case rec[0] == csvSummaryMarker:
			sawMarker = true
		case rec[0] == "#meta:findings_count":
			sawMeta = true
			assert.Equal(t, "1", rec[1])
		case rec[0] == "#rule:test-rule":
			sawRule = true
			groupTotal += atoi(t, rec[1])
		case rec[0] == "#tag:tag1":
			sawTag = true
			assert.Equal(t, "1", rec[1])
		case rec[0] == "#file:auth.py":
			sawFile = true
			assert.Equal(t, "1", rec[1])
		}
	}
	assert.True(t, sawMarker)
	assert.True(t, sawMeta)
	assert.True(t, sawRule)
	assert.True(t, sawTag)
	assert.True(t, sawFile)
	assert.Equal(t, 1, groupTotal)
}

func TestCSVWithSummaryZeroFindings(t *testing.T) {
	summary, _ := testSummary()
	out := writeReport(t, &CsvReporter{}, []Finding{}, summary)

	// A zero-finding scan still emits a legal header plus the summary.
	reader := csv.NewReader(strings.NewReader(out))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(records), 2)
	assert.Equal(t, "RuleID", records[0][0])
	assert.Equal(t, csvSummaryMarker, records[1][0])
}

func TestCSVWithTruncation(t *testing.T) {
	findings := []Finding{
		{RuleID: "rule-a", File: "a"},
		{RuleID: "rule-b", File: "b"},
		{RuleID: "rule-c", File: "c"},
	}
	summary := NewScanSummary(ScanMeta{Version: "v9.9.9"}, findings,
		SummaryOptions{ByRule: true, GroupLimit: 1})

	out := writeReport(t, &CsvReporter{}, findings, summary)
	assert.Contains(t, out, "#meta:groups_truncated")
	assert.Contains(t, out, "#meta:rule_total")
}

func TestJunitWithSummary(t *testing.T) {
	summary, findings := testSummary()
	out := writeReport(t, &JunitReporter{}, findings, summary)

	var suites struct {
		XMLName   xml.Name `xml:"testsuites"`
		TestSuite []struct {
			Tests      string `xml:"tests,attr"`
			Failures   string `xml:"failures,attr"`
			Properties *struct {
				Property []struct {
					Name  string `xml:"name,attr"`
					Value string `xml:"value,attr"`
				} `xml:"property"`
			} `xml:"properties"`
			TestCases []struct{} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	require.NoError(t, xml.Unmarshal([]byte(out), &suites))
	require.Len(t, suites.TestSuite, 1)
	require.NotNil(t, suites.TestSuite[0].Properties)

	props := map[string]string{}
	for _, p := range suites.TestSuite[0].Properties.Property {
		props[p.Name] = p.Value
	}
	assert.Equal(t, "2", props["gitleaks.findings_count"])
	assert.Equal(t, "3", props["gitleaks.commits_scanned"])
	assert.Equal(t, "v9.9.9", props["gitleaks.tool_version"])
	assert.Equal(t, DefaultConfigIdentity, props["gitleaks.config"])
	assert.Equal(t, "git", props["gitleaks.source_type"])
	assert.Equal(t, "1", props["gitleaks.rule.test-rule"])
	assert.Equal(t, "1", props["gitleaks.rule.other-rule"])
	assert.Len(t, suites.TestSuite[0].TestCases, 2)
}

func TestJunitWithSummaryZeroFindings(t *testing.T) {
	summary, _ := testSummary()
	out := writeReport(t, &JunitReporter{}, []Finding{}, summary)
	var suites struct {
		TestSuite []struct {
			Tests      string `xml:"tests,attr"`
			Properties *struct {
				Property []struct {
					Name string `xml:"name,attr"`
				} `xml:"property"`
			} `xml:"properties"`
		} `xml:"testsuite"`
	}
	require.NoError(t, xml.Unmarshal([]byte(out), &suites))
	require.Len(t, suites.TestSuite, 1)
	assert.Equal(t, "0", suites.TestSuite[0].Tests)
	require.NotNil(t, suites.TestSuite[0].Properties)
}

func TestSarifWithSummary(t *testing.T) {
	summary, findings := testSummary()
	out := writeReport(t, &SarifReporter{}, findings, summary)

	var sarif struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name            string `json:"name"`
					SemanticVersion string `json:"semanticVersion"`
				} `json:"driver"`
			} `json:"tool"`
			Results    []map[string]any `json:"results"`
			Properties *struct {
				ScanSummary *ScanSummary `json:"gitleaks/scanSummary"`
			} `json:"properties"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &sarif))
	require.Len(t, sarif.Runs, 1)
	// The injected build version replaces the legacy hard-coded constant.
	assert.Equal(t, "gitleaks", sarif.Runs[0].Tool.Driver.Name)
	assert.Equal(t, "v9.9.9", sarif.Runs[0].Tool.Driver.SemanticVersion)
	assert.Len(t, sarif.Runs[0].Results, 2)
	require.NotNil(t, sarif.Runs[0].Properties)
	require.NotNil(t, sarif.Runs[0].Properties.ScanSummary)
	assert.Equal(t, 2, sarif.Runs[0].Properties.ScanSummary.FindingsCount)
}

// Existing templates must render byte-identical output even when a summary
// is attached, because the template context itself is unchanged.
func TestTemplateExistingTemplatesUnaffectedBySummary(t *testing.T) {
	tests := []struct {
		name    string
		finding Finding
	}{
		{
			name: "markdown",
			finding: Finding{
				RuleID:      "test-rule",
				Description: "A test rule",
				Match:       "line containing secret",
				Secret:      "a secret",
				StartLine:   1,
				EndLine:     2,
				StartColumn: 1,
				EndColumn:   2,
				Message:     "opps",
				File:        "auth.py",
				Commit:      "0000000000000000",
				Author:      "John Doe",
				Email:       "johndoe@gmail.com",
				Date:        "10-19-2003",
				Tags:        []string{"tag1", "tag2", "tag3"},
			},
		},
		{
			name: "jsonextra",
			finding: Finding{
				RuleID:      "test-rule",
				Description: "A test rule",
				Line:        "whole line containing secret",
				Match:       "line containing secret",
				Secret:      "a secret",
				StartLine:   1,
				EndLine:     2,
				StartColumn: 1,
				EndColumn:   2,
				Message:     "opps",
				File:        "auth.py",
				Commit:      "0000000000000000",
				Author:      "John Doe",
				Email:       "johndoe@gmail.com",
				Date:        "10-19-2003",
				Tags:        []string{"tag1", "tag2", "tag3"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			summary, _ := testSummary()
			reporter, err := NewTemplateReporter(templatePath + test.name + ".tmpl")
			require.NoError(t, err)
			out := writeReport(t, reporter, []Finding{test.finding}, summary)

			want, err := os.ReadFile(filepath.Join(expectPath, "report", "template_"+test.name+".json"))
			if err != nil {
				want, err = os.ReadFile(filepath.Join(expectPath, "report", "template_"+test.name+".md"))
			}
			require.NoError(t, err)
			assert.Equal(t,
				lineEndingReplacer.Replace(string(want)),
				lineEndingReplacer.Replace(out),
			)
		})
	}
}

func TestTemplateCanAccessSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.tmpl")
	require.NoError(t, os.WriteFile(path, []byte(
		`findings={{ len . }} version={{ (gitleaksSummary).Tool.Version }} rule:test-rule={{ (index (gitleaksSummary).Groups.ByRule.Counts 0).Count }}`,
	), 0o600))

	reporter, err := NewTemplateReporter(path)
	require.NoError(t, err)
	summary := NewScanSummary(ScanMeta{Version: "v9.9.9"},
		[]Finding{{RuleID: "test-rule"}}, SummaryOptions{ByRule: true})
	assert.Equal(t, "findings=1 version=v9.9.9 rule:test-rule=1",
		writeReport(t, reporter, []Finding{{RuleID: "test-rule"}}, summary))
}

func TestTemplateSummaryFunctionNilWhenDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.tmpl")
	require.NoError(t, os.WriteFile(path, []byte(
		`{{ if gitleaksSummary }}on{{ else }}off{{ end }}`,
	), 0o600))

	reporter, err := NewTemplateReporter(path)
	require.NoError(t, err)
	assert.Equal(t, "off", writeReport(t, reporter, []Finding{}, nil))
}
