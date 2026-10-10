package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/h2non/filetype"
	kczip "github.com/klauspost/compress/zip"
	"github.com/mholt/archives"
	"github.com/rs/zerolog"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const defaultBufferSize = 100 * 1_000 // 100kb
const InnerPathSeparator = "!"

type seekReaderAt interface {
	io.ReaderAt
	io.Seeker
}

// File is a source for yielding fragments from a file or other reader
type File struct {
	// Content provides a reader to the file's content
	Content io.Reader
	// Path is the resolved real path of the file
	Path string
	// Symlink represents a symlink to the file if that's how it was discovered
	Symlink string
	// Buffer is used for reading the content in chunks
	Buffer []byte
	// Config is the gitleaks config used for shouldSkipPath. If not set, then
	// shouldSkipPath is ignored
	Config *config.Config
	// outerPaths is the list of container paths (e.g. archives) that lead to
	// this file
	outerPaths []string
	// MaxArchiveDepth limits how deep the sources will explore nested archives
	MaxArchiveDepth int
	// archiveDepth is the current archive nesting depth
	archiveDepth int
	// ArchiveLimits configures the extraction limits applied to archives
	// encountered by this file. The same configuration may be shared across
	// File sources; per-archive accounting is tracked separately.
	ArchiveLimits *ArchiveLimits
}

// Fragments yields fragments for the this source
func (s *File) Fragments(ctx context.Context, yield FragmentsFunc) error {
	format, _, err := archives.Identify(ctx, s.Path, nil)
	// Process the file as an archive if there's no error && Identify returns
	// a format; but if there's an error or no format, just swallow the error
	// and fall back on treating it like a normal file and let fileFragments
	// decide what to do with it.
	if err == nil && format != nil {
		if s.archiveDepth+1 > s.MaxArchiveDepth {
			var event *zerolog.Event

			// Warn if the feature is enabled; else emit a trace log.
			if s.MaxArchiveDepth != 0 {
				event = logging.Warn()
			} else {
				event = logging.Trace()
			}

			event.Str(
				"path", s.FullPath(),
			).Int(
				"max_archive_depth", s.MaxArchiveDepth,
			).Msg("skipping archive: exceeds max archive depth")

			return nil
		}
		if extractor, ok := format.(archives.Extractor); ok {
			return s.extractorFragments(ctx, extractor, s.Content, yield)
		}
		if decompressor, ok := format.(archives.Decompressor); ok {
			return s.decompressorFragments(ctx, decompressor, s.Content, yield)
		}
		logging.Warn().Str("path", s.FullPath()).Msg("skipping unknown archive type")
	}

	return s.fileFragments(ctx, bufio.NewReader(s.Content), yield)
}

// extractorFragments recursively crawls archives and yields fragments
func (s *File) extractorFragments(ctx context.Context, extractor archives.Extractor, reader io.Reader, yield FragmentsFunc) error {
	if _, isSeekReaderAt := reader.(seekReaderAt); !isSeekReaderAt {
		switch extractor.(type) {
		case archives.SevenZip, archives.Zip:
			tmpfile, err := os.CreateTemp("", "gitleaks-archive-")
			if err != nil {
				logging.Error().Str("path", s.FullPath()).Msg("could not create tmp file")
				return nil
			}
			defer func() {
				_ = tmpfile.Close()
				_ = os.Remove(tmpfile.Name())
			}()

			_, err = io.Copy(tmpfile, reader)
			if err != nil {
				logging.Error().Str("path", s.FullPath()).Msg("could not copy archive file")
				return nil
			}

			reader = tmpfile
		}
	}

	// Per-archive accounting; fresh state for every archive so that limits
	// never carry across sibling archives.
	st := newArchiveState(s.ArchiveLimits)

	err := extractor.Extract(ctx, reader, func(_ context.Context, d archives.FileInfo) error {
		if d.IsDir() {
			return nil
		}

		entryPath := normalizeInnerPath(d.NameInArchive)

		// Once this archive has hit a limit, every remaining entry is skipped.
		if st.triggered() {
			return errArchiveLimit
		}

		// Count the entry (including allowlisted entries) and enforce the
		// per-archive entry-count limit.
		entryCount := st.entries.Add(1)
		if st.limits != nil && st.limits.MaxEntries > 0 && entryCount > st.limits.MaxEntries {
			return s.onLimit(st, entryPath, yield, "max archive entries exceeded")
		}

		// Uncompressed size of the entry.
		size := d.Size()

		// Enforce the per-entry size limit.
		if st.limits != nil && st.limits.MaxEntryBytes > 0 && size > st.limits.MaxEntryBytes {
			return s.onLimit(st, entryPath, yield, "max archive entry size exceeded")
		}

		// Enforce the compression-ratio limit where per-entry compressed
		// sizes are known.
		if st.limits != nil && st.limits.MaxCompressionRatio > 0 &&
			compressionRatioExceeded(d, size, st.limits.MaxCompressionRatio) {
			return s.onLimit(st, entryPath, yield, "max archive compression ratio exceeded")
		}

		// Enforce the per-archive total-size limit before reading the entry.
		if st.limits != nil && st.limits.MaxTotalBytes > 0 && size >= 0 &&
			st.totalBytes.Load()+size > st.limits.MaxTotalBytes {
			return s.onLimit(st, entryPath, yield, "max archive total size exceeded")
		}

		innerReader, err := d.Open()
		if err != nil {
			logging.Error().Err(err).Str("path", s.FullPath()).Msg("could not open archive inner file")
			return nil
		}
		defer innerReader.Close()

		if s.Config != nil && shouldSkipPath(s.Config, entryPath) {
			logging.Debug().Str("path", s.FullPath()).Msg("skipping file: global allowlist")
			return nil
		}

		// Count bytes actually read so totals stay accurate even when an
		// archive ends midway through extraction.
		counted := countingReader{reader: innerReader, add: st.addBytes}

		file := &File{
			Content:         counted,
			Path:            entryPath,
			Symlink:         s.Symlink,
			outerPaths:      append(s.outerPaths, filepath.ToSlash(s.Path)),
			MaxArchiveDepth: s.MaxArchiveDepth,
			archiveDepth:    s.archiveDepth + 1,
			ArchiveLimits:   s.ArchiveLimits,
		}

		if err := file.Fragments(ctx, yield); err != nil {
			return err
		}

		return nil
	})

	if errors.Is(err, errArchiveLimit) {
		return nil
	}
	return err
}

// decompressorFragments recursively crawls archives and yields fragments
func (s *File) decompressorFragments(ctx context.Context, decompressor archives.Decompressor, reader io.Reader, yield FragmentsFunc) error {
	innerReader, err := decompressor.OpenReader(reader)
	if err != nil {
		logging.Error().Str("path", s.FullPath()).Msg("could read compressed file")
		return nil
	}

	// Per-archive accounting; the decompressed stream is a single entry.
	st := newArchiveState(s.ArchiveLimits)
	st.entries.Add(1)

	source := io.Reader(innerReader)
	if st.limits != nil && (st.limits.MaxEntryBytes > 0 || st.limits.MaxTotalBytes > 0) {
		source = &limitedReader{
			reader:      innerReader,
			st:          st,
			archivePath: s.FullPath(),
		}
	}

	if err := s.fileFragments(ctx, bufio.NewReader(source), yield); err != nil {
		_ = innerReader.Close()
		return err
	}

	_ = innerReader.Close()
	return nil
}

// fileFragments reads the file into fragments to yield
func (s *File) fileFragments(ctx context.Context, reader *bufio.Reader, yield FragmentsFunc) error {
	// Create a buffer if the caller hasn't provided one
	if s.Buffer == nil {
		s.Buffer = make([]byte, defaultBufferSize)
	}

	totalLines := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fragment := Fragment{
				FilePath: s.FullPath(),
			}

			n, err := reader.Read(s.Buffer)
			if n == 0 {
				if err != nil && err != io.EOF {
					return yield(fragment, fmt.Errorf("could not read file: %w", err))
				}

				return nil
			}

			// Only check the filetype at the start of file.
			if totalLines == 0 {
				// TODO: could other optimizations be introduced here?
				if mimetype, err := filetype.Match(s.Buffer[:n]); err != nil {
					return yield(
						fragment,
						fmt.Errorf("could not read file: could not determine type: %w", err),
					)
				} else if mimetype.MIME.Type == "application" {
					logging.Debug().
						Str("mime_type", mimetype.MIME.Value).
						Str("path", s.FullPath()).
						Msgf("skipping binary file")

					return nil
				}
			}

			// Try to split chunks across large areas of whitespace, if possible.
			peekBuf := bytes.NewBuffer(s.Buffer[:n])
			if err := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); err != nil {
				return yield(
					fragment,
					fmt.Errorf("could not read file: could not read until safe boundary: %w", err),
				)
			}

			fragment.Raw = peekBuf.String()
			fragment.Bytes = peekBuf.Bytes()
			fragment.StartLine = totalLines + 1

			// Count the number of newlines in this chunk
			totalLines += strings.Count(fragment.Raw, "\n")

			if len(s.Symlink) > 0 {
				fragment.SymlinkFile = s.Symlink
			}

			if isWindows && len(s.outerPaths) == 0 {
				// Only top-level files carry OS separators; nested full paths are
				// slash-normalized (and may contain escaped backslashes).
				fragment.FilePath = filepath.ToSlash(fragment.FilePath)
				fragment.SymlinkFile = filepath.ToSlash(s.Symlink)
				// Preserve the path with the original separator.
				fragment.WindowsFilePath = s.Path
			}

			// log errors but continue since there's content
			if err != nil && err != io.EOF {
				logging.Warn().Err(err).Msgf("issue reading file")
			}

			// Done with the file!
			if err == io.EOF {
				return yield(fragment, nil)
			}

			if err := yield(fragment, err); err != nil {
				return err
			}
		}
	}
}

// FullPath returns the File.Path with any preceding outer paths.
//
// Every path segment is escaped via encodePathSegment and joined with
// InnerPathSeparator, so the result can always be restored with SplitFullPath
// even when a segment contains "!" or "\".
func (s *File) FullPath() string {
	if len(s.outerPaths) > 0 {
		segments := make([]string, 0, len(s.outerPaths)+1)
		// outerPaths have already been normalized to slash
		for _, p := range s.outerPaths {
			segments = append(segments, encodePathSegment(p))
		}
		segments = append(segments, encodePathSegment(s.Path))
		return strings.Join(segments, InnerPathSeparator)
	}

	// Top-level full paths are slash normalized regardless of host OS.
	if isWindows {
		return filepath.ToSlash(s.Path)
	}
	return s.Path
}

// -----------------------------------------------------------------------------
// Inner path encoding
// -----------------------------------------------------------------------------

// normalizeInnerPath returns the platform-independent, slash-cleaned form of
// an archive entry path.
//
// "/" is the only directory separator (per the zip/tar conventions); a literal
// backslash is preserved as-is and later escaped. This keeps entry paths
// identical regardless of the host operating system.
func normalizeInnerPath(name string) string {
	return path.Clean(name)
}

// encodePathSegment escapes a single path segment so that segments can be
// joined with InnerPathSeparator and split again unambiguously:
//
//	"\" -> "\\"
//	"!" -> "\!"
func encodePathSegment(segment string) string {
	segment = strings.ReplaceAll(segment, `\`, `\\`)
	segment = strings.ReplaceAll(segment, InnerPathSeparator, `\`+InnerPathSeparator)
	return segment
}

// decodePathSegment reverses encodePathSegment.
func decodePathSegment(segment string) string {
	var b strings.Builder
	for i := 0; i < len(segment); i++ {
		if segment[i] == '\\' && i+1 < len(segment) {
			switch segment[i+1] {
			case '\\', '!':
				b.WriteByte(segment[i+1])
				i++
				continue
			}
		}
		b.WriteByte(segment[i])
	}
	return b.String()
}

// SplitFullPath splits a full path (as returned by File.FullPath) into its
// original path segments — outer container paths followed by inner entry
// paths — unescaping each. Boundaries are unescaped "!" characters, so a
// literal "!" or "\" inside a layer is restored correctly at every depth.
func SplitFullPath(full string) []string {
	var (
		segments []string
		b        strings.Builder
	)
	for i := 0; i < len(full); i++ {
		switch full[i] {
		case '\\':
			if i+1 < len(full) && (full[i+1] == '\\' || full[i+1] == '!') {
				b.WriteByte(full[i])
				b.WriteByte(full[i+1])
				i++
				continue
			}
			b.WriteByte(full[i])
		case '!':
			segments = append(segments, decodePathSegment(b.String()))
			b.Reset()
		default:
			b.WriteByte(full[i])
		}
	}
	return append(segments, decodePathSegment(b.String()))
}

// -----------------------------------------------------------------------------
// Archive extraction limits
// -----------------------------------------------------------------------------

// ArchiveLimitAction determines what happens when an archive reaches a
// configured extraction limit.
type ArchiveLimitAction string

const (
	// ArchiveLimitSkipEntries stops extracting further entries from the
	// archive; the triggering entry and all remaining entries are skipped.
	ArchiveLimitSkipEntries ArchiveLimitAction = "skip-entries"
	// ArchiveLimitSkipArchive behaves like ArchiveLimitSkipEntries and also
	// suppresses findings already reported from the archive.
	ArchiveLimitSkipArchive ArchiveLimitAction = "skip-archive"
	// ArchiveLimitAbortSource aborts the source with an error.
	ArchiveLimitAbortSource ArchiveLimitAction = "abort-source"
)

// ArchiveLimits configures extraction limits for a single archive.
//
// Zero values mean the corresponding limit is not set.
type ArchiveLimits struct {
	// MaxEntryBytes limits the uncompressed size of a single inner entry.
	MaxEntryBytes int64
	// MaxTotalBytes limits the total uncompressed bytes extracted from a
	// single archive.
	MaxTotalBytes int64
	// MaxEntries limits the number of entries extracted from a single
	// archive.
	MaxEntries int64
	// MaxCompressionRatio limits the uncompressed/compressed size ratio of
	// an entry. It is enforced wherever per-entry compressed sizes are known
	// (e.g. zip entries).
	MaxCompressionRatio float64
	// OnLimit is the action performed once any limit is reached.
	// Defaults to ArchiveLimitSkipEntries.
	OnLimit ArchiveLimitAction
}

// Validate verifies the limits. Zero values are treated as "not set";
// explicitly-set values must be positive.
func (l *ArchiveLimits) Validate() error {
	if l.MaxEntryBytes < 0 {
		return errors.New("max archive entry size must not be negative")
	}
	if l.MaxTotalBytes < 0 {
		return errors.New("max archive total size must not be negative")
	}
	if l.MaxEntries < 0 {
		return errors.New("max archive entries must not be negative")
	}
	if l.MaxCompressionRatio < 0 {
		return errors.New("max archive compression ratio must not be negative")
	}
	switch l.OnLimit {
	case "",
		ArchiveLimitSkipEntries,
		ArchiveLimitSkipArchive,
		ArchiveLimitAbortSource:
	default:
		return fmt.Errorf("unknown archive limit action %q", l.OnLimit)
	}
	return nil
}

// action returns the configured action, defaulting to ArchiveLimitSkipEntries.
func (l *ArchiveLimits) action() ArchiveLimitAction {
	if l == nil || l.OnLimit == "" {
		return ArchiveLimitSkipEntries
	}
	return l.OnLimit
}

// ArchiveLimitError indicates that archive extraction reached a configured
// limit. For ArchiveLimitAbortSource it is returned as the source error; for
// the skip actions it is yielded to the fragment callback exactly once.
type ArchiveLimitError struct {
	// Archive is the full path of the archive that reached the limit.
	Archive string
	// Inner is the inner entry path that triggered the limit.
	Inner string
	// Action is the configured limit action.
	Action ArchiveLimitAction
	// Reason describes the limit that was reached.
	Reason string
}

func (e *ArchiveLimitError) Error() string {
	if e.Inner != "" {
		return fmt.Sprintf("archive extraction limit reached (%s): %s!%s", e.Reason, e.Archive, e.Inner)
	}
	return fmt.Sprintf("archive extraction limit reached (%s): %s", e.Reason, e.Archive)
}

// errArchiveLimit is the sentinel returned from an extractor's file handler to
// stop walking the archive once a limit has been reached. It is swallowed by
// extractorFragments so the rest of the scan continues.
var errArchiveLimit = errors.New("archive extraction limit reached")

// archiveState holds per-archive extraction accounting. A fresh state is
// created for each archive; sibling archives never share accounting.
type archiveState struct {
	limits *ArchiveLimits

	// totalBytes counts bytes actually extracted from the archive.
	totalBytes atomic.Int64
	// entries counts entries encountered in the archive.
	entries atomic.Int64

	// Ensures the limit is recorded (and acted upon) exactly once.
	once       sync.Once
	triggered2 atomic.Bool
	reason     string
}

func newArchiveState(limits *ArchiveLimits) *archiveState {
	return &archiveState{limits: limits}
}

func (st *archiveState) addBytes(n int64) int64 {
	return st.totalBytes.Add(n)
}

// triggered reports whether a limit has already been reached.
func (st *archiveState) triggered() bool {
	return st.triggered2.Load()
}

// trigger records the limit reason exactly once. It returns true only for the
// caller that recorded the limit.
func (st *archiveState) trigger(reason string) bool {
	fired := false
	st.once.Do(func() {
		st.reason = reason
		st.triggered2.Store(true)
		fired = true
	})
	return fired
}

// onLimit enforces the configured action exactly once for the archive and
// returns the error to return from the extractor's file handler.
func (s *File) onLimit(st *archiveState, innerPath string, yield FragmentsFunc, reason string) error {
	if !st.trigger(reason) {
		// Limit already recorded by an earlier check.
		return errArchiveLimit
	}

	limitErr := &ArchiveLimitError{
		Archive: s.FullPath(),
		Inner:   innerPath,
		Action:  st.limits.action(),
		Reason:  st.reason,
	}

	// Yield the structured error exactly once so the detector can log,
	// suppress findings, or propagate an abort.
	if err := yield(Fragment{}, limitErr); err != nil {
		return err
	}

	if limitErr.Action == ArchiveLimitAbortSource {
		return limitErr
	}

	// Stop the archive walk; the sentinel is swallowed by extractorFragments.
	return errArchiveLimit
}

// countingReader reports read bytes through |add|.
type countingReader struct {
	reader io.Reader
	add    func(int64) int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if n > 0 {
		c.add(int64(n))
	}
	return n, err
}

// limitedReader bounds the decompressed bytes of a decompressor source.
type limitedReader struct {
	reader      io.Reader
	st          *archiveState
	archivePath string
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.st.triggered() {
		// Limit already communicated; end the stream quietly.
		return 0, io.EOF
	}

	limit := l.byteLimit()
	if remaining := limit - l.st.totalBytes.Load(); remaining <= 0 {
		return 0, l.fire("max archive bytes exceeded")
	} else if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	n, err := l.reader.Read(p)
	if n > 0 {
		l.st.addBytes(int64(n))
	}
	return n, err
}

// byteLimit returns the effective per-stream byte limit.
func (l *limitedReader) byteLimit() int64 {
	limits := l.st.limits
	switch {
	case limits.MaxEntryBytes > 0 && limits.MaxTotalBytes > 0:
		if limits.MaxEntryBytes < limits.MaxTotalBytes {
			return limits.MaxEntryBytes
		}
		return limits.MaxTotalBytes
	case limits.MaxEntryBytes > 0:
		return limits.MaxEntryBytes
	default:
		return limits.MaxTotalBytes
	}
}

// fire records the limit once and returns the structured ArchiveLimitError for
// the fragment callback, or io.EOF if the limit was already recorded.
func (l *limitedReader) fire(reason string) error {
	if !l.st.trigger(reason) {
		return io.EOF
	}
	return &ArchiveLimitError{
		Archive: l.archivePath,
		Action:  l.st.limits.action(),
		Reason:  reason,
	}
}

// compressionRatioExceeded reports whether the entry's uncompressed/compressed
// ratio exceeds |max|. Entries without a known compressed size are ignored.
func compressionRatioExceeded(d archives.FileInfo, uncompressed int64, max float64) bool {
	compressed, ok := entryCompressedSize(d)
	if !ok {
		return false
	}
	switch {
	case compressed == 0 && uncompressed > 0:
		// Effectively an infinite ratio.
		return true
	case compressed == 0:
		return false
	default:
		return float64(uncompressed)/float64(compressed) > max
	}
}

// entryCompressedSize returns the compressed size of an entry where the
// archive format reports it. The header may be presented as a value or
// pointer.
func entryCompressedSize(d archives.FileInfo) (int64, bool) {
	switch h := d.Header.(type) {
	case kczip.FileHeader:
		if h.CompressedSize64 == 0 && h.UncompressedSize64 == 0 {
			return 0, false
		}
		return int64(h.CompressedSize64), true
	case *kczip.FileHeader:
		if h.CompressedSize64 == 0 && h.UncompressedSize64 == 0 {
			return 0, false
		}
		return int64(h.CompressedSize64), true
	}
	return 0, false
}
