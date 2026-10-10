package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

type CsvReporter struct {
	SummarySettings
}

var _ Reporter = (*CsvReporter)(nil)

// Summary rows always start with this marker in the RuleID column so
// existing parsers can distinguish them from finding rows without the
// column layout changing.
const csvSummaryMarker = "#gitleaks-scan-summary"

func (r *CsvReporter) Write(w io.WriteCloser, findings []Finding) error {
	if len(findings) == 0 && r.Summary == nil {
		return nil
	}

	var (
		cw  = csv.NewWriter(w)
		err error
	)
	columns := []string{"RuleID",
		"Commit",
		"File",
		"SymlinkFile",
		"Secret",
		"Match",
		"StartLine",
		"EndLine",
		"StartColumn",
		"EndColumn",
		"Author",
		"Message",
		"Date",
		"Email",
		"Fingerprint",
		"Tags",
	}
	// A miserable attempt at "omitempty" so tests don't yell at me.
	hasLink := len(findings) > 0 && findings[0].Link != ""
	if hasLink {
		columns = append(columns, "Link")
	}

	if err = cw.Write(columns); err != nil {
		return err
	}
	for _, f := range findings {
		row := []string{f.RuleID,
			f.Commit,
			f.File,
			f.SymlinkFile,
			f.Secret,
			f.Match,
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			f.Author,
			f.Message,
			f.Date,
			f.Email,
			f.Fingerprint,
			strings.Join(f.Tags, " "),
		}
		if hasLink {
			row = append(row, f.Link)
		}

		if err = cw.Write(row); err != nil {
			return err
		}
	}

	if r.Summary != nil {
		for _, row := range r.summaryRows(len(columns)) {
			if err = cw.Write(row); err != nil {
				return err
			}
		}
	}

	cw.Flush()
	return cw.Error()
}

// summaryRows renders the summary as CSV records padded to the report's
// column count so the existing columns and parsing are preserved. The key
// goes in the first column and the value in the second column.
func (r *CsvReporter) summaryRows(arity int) [][]string {
	s := r.Summary
	row := func(key, value string) []string {
		rec := make([]string, arity)
		rec[0] = key
		rec[1] = value
		return rec
	}

	rows := [][]string{row(csvSummaryMarker, "")}
	rows = append(rows,
		row("#meta:findings_count", strconv.Itoa(s.FindingsCount)),
		row("#meta:bytes_scanned", strconv.FormatUint(s.BytesScanned, 10)),
		row("#meta:commits_scanned", strconv.Itoa(s.CommitsScanned)),
		row("#meta:generated_at", s.GeneratedAt.Format("2006-01-02T15:04:05Z07:00")),
		row("#meta:tool_name", s.Tool.Name),
		row("#meta:tool_version", s.Tool.Version),
		row("#meta:config", s.Config.Identity),
		row("#meta:source_type", s.Source.Type),
		row("#meta:source_path", s.Source.Path),
	)

	var truncated []string
	addGroups := func(prefix string, gc *GroupCounts) {
		if gc == nil {
			return
		}
		for _, c := range gc.Counts {
			rows = append(rows, row("#"+prefix+":"+c.Key, strconv.Itoa(c.Count)))
		}
		if gc.Limited {
			truncated = append(truncated, prefix)
			rows = append(rows, row("#meta:"+prefix+"_total", strconv.Itoa(gc.Total)))
		}
	}
	addGroups(GroupByRule, s.Groups.ByRule)
	addGroups(GroupByTag, s.Groups.ByTag)
	addGroups(GroupByFile, s.Groups.ByFile)

	if len(truncated) > 0 {
		rows = append(rows, row("#meta:groups_truncated", strings.Join(truncated, ";")))
	}

	return rows
}
