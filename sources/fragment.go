package sources

// Fragment represents a fragment of a source with its meta data
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	Bytes []byte

	// FilePath is the path to the file if applicable.
	// The path separator MUST be normalized to `/`.
	FilePath    string
	SymlinkFile string
	// WindowsFilePath is the path with the original separator.
	// This provides a backwards-compatible solution to https://github.com/gitleaks/gitleaks/issues/1565.
	WindowsFilePath string `json:"-"` // TODO: remove this in v9.

	// CommitSHA is the SHA of the commit if applicable
	CommitSHA string // TODO: remove this in v9 and use CommitInfo instead

	// CommitOrder is the position of the commit in the input stream.
	// It is assigned by the source when the commit is first seen (starting
	// at 1) and carried by every fragment of that commit, so findings can
	// be ordered by commit without relying on completion order or guessing
	// from the SHA. Fragments without a commit source leave this at 0.
	CommitOrder int

	// StartLine is the line number this fragment starts on
	StartLine int

	// CommitInfo captures additional information about the git commit if applicable
	CommitInfo *CommitInfo

	InheritedFromFinding bool // Indicates if this fragment is inherited from a finding
}
