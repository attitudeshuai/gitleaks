package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type JunitReporter struct {
	SummarySettings
}

var _ Reporter = (*JunitReporter)(nil)

func (r *JunitReporter) Write(w io.WriteCloser, findings []Finding) error {
	testSuites := TestSuites{
		TestSuites: r.getTestSuites(findings),
	}

	io.WriteString(w, xml.Header)
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "\t")
	return encoder.Encode(testSuites)
}

func (r *JunitReporter) getTestSuites(findings []Finding) []TestSuite {
	return []TestSuite{
		{
			Failures:   strconv.Itoa(len(findings)),
			Name:       "gitleaks",
			Tests:      strconv.Itoa(len(findings)),
			Properties: r.getProperties(),
			TestCases:  getTestCases(findings),
			Time:       "",
		},
	}
}

// getProperties renders the scan summary as JUnit testsuite properties.
// Returns nil when no summary is attached so output stays byte-identical.
func (r *JunitReporter) getProperties() *JunitProperties {
	if r.Summary == nil {
		return nil
	}

	s := r.Summary
	props := []JunitProperty{
		{Name: "gitleaks.findings_count", Value: strconv.Itoa(s.FindingsCount)},
		{Name: "gitleaks.bytes_scanned", Value: strconv.FormatUint(s.BytesScanned, 10)},
		{Name: "gitleaks.commits_scanned", Value: strconv.Itoa(s.CommitsScanned)},
		{Name: "gitleaks.generated_at", Value: s.GeneratedAt.Format("2006-01-02T15:04:05Z07:00")},
		{Name: "gitleaks.tool_name", Value: s.Tool.Name},
		{Name: "gitleaks.tool_version", Value: s.Tool.Version},
		{Name: "gitleaks.config", Value: s.Config.Identity},
		{Name: "gitleaks.source_type", Value: s.Source.Type},
		{Name: "gitleaks.source_path", Value: s.Source.Path},
	}

	var truncated []string
	addGroups := func(name string, gc *GroupCounts) {
		if gc == nil {
			return
		}
		for _, c := range gc.Counts {
			props = append(props, JunitProperty{Name: "gitleaks." + name + "." + c.Key, Value: strconv.Itoa(c.Count)})
		}
		if gc.Limited {
			truncated = append(truncated, name)
			props = append(props, JunitProperty{
				Name:  "gitleaks." + name + ".total",
				Value: strconv.Itoa(gc.Total),
			})
		}
	}
	addGroups(GroupByRule, s.Groups.ByRule)
	addGroups(GroupByTag, s.Groups.ByTag)
	addGroups(GroupByFile, s.Groups.ByFile)

	if len(truncated) > 0 {
		props = append(props, JunitProperty{
			Name:  "gitleaks.groups_truncated",
			Value: strings.Join(truncated, ";"),
		})
	}

	return &JunitProperties{Properties: props}
}

func getTestCases(findings []Finding) []TestCase {
	testCases := []TestCase{}
	for _, f := range findings {
		testCase := TestCase{
			Classname: f.Description,
			Failure:   getFailure(f),
			File:      f.File,
			Name:      getMessage(f),
			Time:      "",
		}
		testCases = append(testCases, testCase)
	}
	return testCases
}

func getFailure(f Finding) Failure {
	return Failure{
		Data:    getData(f),
		Message: getMessage(f),
		Type:    f.Description,
	}
}

func getData(f Finding) string {
	data, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(data)
}

func getMessage(f Finding) string {
	if f.Commit == "" {
		return fmt.Sprintf("%s has detected a secret in file %s, line %s.", f.RuleID, f.File, strconv.Itoa(f.StartLine))
	}

	return fmt.Sprintf("%s has detected a secret in file %s, line %s, at commit %s.", f.RuleID, f.File, strconv.Itoa(f.StartLine), f.Commit)
}

type TestSuites struct {
	XMLName    xml.Name `xml:"testsuites"`
	TestSuites []TestSuite
}

type TestSuite struct {
	XMLName    xml.Name         `xml:"testsuite"`
	Failures   string           `xml:"failures,attr"`
	Name       string           `xml:"name,attr"`
	Tests      string           `xml:"tests,attr"`
	Properties *JunitProperties `xml:"properties,omitempty"`
	TestCases  []TestCase       `xml:"testcase"`
	Time       string           `xml:"time,attr"`
}

type JunitProperties struct {
	XMLName    xml.Name        `xml:"properties"`
	Properties []JunitProperty `xml:"property"`
}

type JunitProperty struct {
	XMLName xml.Name `xml:"property"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:"value,attr"`
}

type TestCase struct {
	XMLName   xml.Name `xml:"testcase"`
	Classname string   `xml:"classname,attr"`
	Failure   Failure  `xml:"failure"`
	File      string   `xml:"file,attr"`
	Name      string   `xml:"name,attr"`
	Time      string   `xml:"time,attr"`
}

type Failure struct {
	XMLName xml.Name `xml:"failure"`
	Data    string   `xml:",chardata"`
	Message string   `xml:"message,attr"`
	Type    string   `xml:"type,attr"`
}
