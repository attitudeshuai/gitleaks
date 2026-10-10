package report

import (
	"sort"
	"strings"
)

// NormalizePath returns the canonical form of a path used for ordering
// findings. It is applied to file identifiers (including archive inner
// paths, e.g. "archive.zip!dir/file") and symlink paths, so the ordering
// does not depend on the platform separator or letter case.
//
// Normalization:
//  1. Backslashes are replaced with forward slashes.
//  2. The result is case-folded.
//
// It never transforms the path stored on the finding; it only produces the
// value used by the ordering comparison.
func NormalizePath(p string) string {
	return strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
}

// Less reports whether finding a must be ordered before finding b.
//
// The ordering key, compared in this sequence, is:
//  1. Commit presence: findings that belong to a commit come first;
//     findings without a commit source follow and are ordered by file and
//     location only.
//  2. CommitOrder: the position of the commit in the input stream, recorded
//     by the source when it yields the fragment.
//  3. File: the normalized file identifier.
//  4. StartLine, EndLine.
//  5. RuleID, so multiple rules matching the same location are ordered by
//     rule identifier.
//  6. StartColumn, EndColumn, normalized SymlinkFile and Secret as final
//     tiebreakers.
//
// The comparison does not mutate either finding.
func Less(a, b Finding) bool {
	// 1. Commit presence.
	aHasCommit, bHasCommit := a.Commit != "", b.Commit != ""
	if aHasCommit != bHasCommit {
		return aHasCommit
	}

	// 2. Position of the commit in the input stream.
	if a.CommitOrder != b.CommitOrder {
		return a.CommitOrder < b.CommitOrder
	}

	// 3. File identifier.
	if aFile, bFile := NormalizePath(a.File), NormalizePath(b.File); aFile != bFile {
		return aFile < bFile
	}

	// 4. Location.
	if a.StartLine != b.StartLine {
		return a.StartLine < b.StartLine
	}
	if a.EndLine != b.EndLine {
		return a.EndLine < b.EndLine
	}

	// 5. Rule identifier.
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}

	// 6. Final tiebreakers.
	if a.StartColumn != b.StartColumn {
		return a.StartColumn < b.StartColumn
	}
	if a.EndColumn != b.EndColumn {
		return a.EndColumn < b.EndColumn
	}
	if aSymlink, bSymlink := NormalizePath(a.SymlinkFile), NormalizePath(b.SymlinkFile); aSymlink != bSymlink {
		return aSymlink < bSymlink
	}
	return a.Secret < b.Secret
}

// SortFindings orders the findings in place according to Less. It is the
// single ordering step performed after all findings have been collected, so
// the result does not depend on task completion order. It is a stable sort:
// findings with identical ordering keys retain their relative order.
//
// It does not change the number of findings or any of their fields.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		return Less(findings[i], findings[j])
	})
}
