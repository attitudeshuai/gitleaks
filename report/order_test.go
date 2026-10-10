package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ruleIDs(findings []Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}

func TestNormalizePath(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"empty":               {input: "", want: ""},
		"backslashes":         {input: `DIR\Sub\File`, want: "dir/sub/file"},
		"archive inner path":  {input: `ARCHIVE.ZIP!DIR\FILE`, want: "archive.zip!dir/file"},
		"already normalized":  {input: "a/b/c", want: "a/b/c"},
		"case folded":         {input: "UPPER/MIXED", want: "upper/mixed"},
		"backslash preserved": {input: `a\B!c\d`, want: "a/b!c/d"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizePath(tt.input))
		})
	}
}

func TestSortFindings(t *testing.T) {
	findings := []Finding{
		// Commit 2: later in the input stream regardless of file name.
		{RuleID: "commit2-z", Commit: "c2", CommitOrder: 2, File: "z.go", StartLine: 1, EndLine: 1},
		// Commit 1, file b.go.
		{RuleID: "commit1-b", Commit: "c1", CommitOrder: 1, File: "b.go", StartLine: 5, EndLine: 5},
		// Commit 1, file a/go, same start line, larger end line.
		{RuleID: "commit1-a-end3", Commit: "c1", CommitOrder: 1, File: `A\GO`, StartLine: 2, EndLine: 3},
		// Commit 1, file a/go, same lines, larger rule id.
		{RuleID: "commit1-a-r2", Commit: "c1", CommitOrder: 1, File: "a/go", StartLine: 2, EndLine: 2},
		// Commit 1, file a/go, same lines, smaller rule id.
		{RuleID: "commit1-a-r1", Commit: "c1", CommitOrder: 1, File: "a/go", StartLine: 2, EndLine: 2},
		// Commit 1, archive inner paths: identical normalized key, secret breaks the tie.
		{RuleID: "commit1-arc", Commit: "c1", CommitOrder: 1, File: `ARC!Foo\B.GO`, StartLine: 1, EndLine: 1, Secret: "s2"},
		{RuleID: "commit1-arc", Commit: "c1", CommitOrder: 1, File: "arc!foo/b.go", StartLine: 1, EndLine: 1, Secret: "s1"},
		// No commit: sorted after all commit findings, by file only.
		{RuleID: "nocommit-z", File: "nogit/z.go", StartLine: 1, EndLine: 1},
		{RuleID: "nocommit-a", File: `NOGIT\a.go`, StartLine: 1, EndLine: 1},
	}

	SortFindings(findings)

	assert.Equal(t, []string{
		"commit1-a-r1",
		"commit1-a-r2",
		"commit1-a-end3",
		"commit1-arc",
		"commit1-arc",
		"commit1-b",
		"commit2-z",
		"nocommit-a",
		"nocommit-z",
	}, ruleIDs(findings))

	// The archive pair with identical keys is ordered by secret.
	assert.Equal(t, "s1", findings[3].Secret)
	assert.Equal(t, "s2", findings[4].Secret)

	// Sorting again must not change the order.
	again := make([]Finding, len(findings))
	copy(again, findings)
	SortFindings(again)
	assert.Equal(t, ruleIDs(findings), ruleIDs(again))
}

func TestSortFindingsEmpty(t *testing.T) {
	// Both nil and empty slices are valid and keep their structure.
	SortFindings(nil)
	empty := []Finding{}
	SortFindings(empty)
	assert.Len(t, empty, 0)
}

func TestLessMixedCommitPresence(t *testing.T) {
	withCommit := Finding{Commit: "c", CommitOrder: 99, File: "z.go", StartLine: 9}
	withoutCommit := Finding{File: "a.go", StartLine: 1}

	// Commit findings come first even when their file/line would sort later.
	assert.True(t, Less(withCommit, withoutCommit))
	assert.False(t, Less(withoutCommit, withCommit))
}

func TestLessIsAValidComparator(t *testing.T) {
	// Spot-check antisymmetry on the primary keys.
	a := Finding{Commit: "c", CommitOrder: 1, File: "a.go", StartLine: 1, EndLine: 1, RuleID: "r1"}
	b := Finding{Commit: "c", CommitOrder: 1, File: "a.go", StartLine: 1, EndLine: 1, RuleID: "r2"}
	require.True(t, Less(a, b))
	require.False(t, Less(b, a))
	require.False(t, Less(a, a))
}
