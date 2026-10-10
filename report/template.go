package report

import (
	"errors"
	"fmt"
	"io"
	"os"
	"text/template"

	"github.com/Masterminds/sprig/v3"
)

// SummaryTemplateFunc is the template function that returns the scan
// summary attached to the report. It returns nil when summaries are
// disabled, so templates can guard with {{ if gitleaksSummary }}.
const SummaryTemplateFunc = "gitleaksSummary"

type TemplateReporter struct {
	SummarySettings
	template *template.Template
}

var _ Reporter = (*TemplateReporter)(nil)

func NewTemplateReporter(templatePath string) (*TemplateReporter, error) {
	if templatePath == "" {
		return nil, errors.New("template path cannot be empty")
	}

	file, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	templateText := string(file)

	// TODO: Add helper functions like escaping for JSON, XML, etc.
	t := template.New("custom")

	funcMap := sprig.TxtFuncMap()
	delete(funcMap, "env")
	delete(funcMap, "expandenv")
	delete(funcMap, "getHostByName")

	reporter := &TemplateReporter{}
	// Expose the scan summary without changing the template context: the
	// root value (".") remains the plain findings slice, so existing
	// templates render exactly as before. The closure reads the field at
	// execution time, after the summary has been attached.
	funcMap[SummaryTemplateFunc] = func() *ScanSummary {
		return reporter.Summary
	}

	t = t.Funcs(funcMap)
	t, err = t.Parse(templateText)
	if err != nil {
		return nil, fmt.Errorf("error parsing file: %w", err)
	}
	reporter.template = t
	return reporter, nil
}

// writeTemplate renders the findings using the user-provided template.
// https://www.digitalocean.com/community/tutorials/how-to-use-templates-in-go
func (t *TemplateReporter) Write(w io.WriteCloser, findings []Finding) error {
	if err := t.template.Execute(w, findings); err != nil {
		return err
	}
	return nil
}
