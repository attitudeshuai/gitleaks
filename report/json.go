package report

import (
	"encoding/json"
	"io"
)

type JsonReporter struct {
	SummarySettings
}

var _ Reporter = (*JsonReporter)(nil)

// jsonReport is the envelope used when a scan summary is enabled.
type jsonReport struct {
	Summary  *ScanSummary `json:"summary"`
	Findings []Finding    `json:"findings"`
}

func (t *JsonReporter) Write(w io.WriteCloser, findings []Finding) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")

	if t.Summary == nil {
		return encoder.Encode(findings)
	}

	// Ensure a zero-finding scan still emits a legal empty array.
	if findings == nil {
		findings = []Finding{}
	}
	return encoder.Encode(jsonReport{
		Summary:  t.Summary,
		Findings: findings,
	})
}
