package sources

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_readUntilSafeBoundary(t *testing.T) {
	// Arrange
	cases := []struct {
		name     string
		r        io.Reader
		expected string
	}{
		// Current split is fine, exit early.
		{
			name:     "safe original split - LF",
			r:        strings.NewReader("abc\n\ndefghijklmnop\n\nqrstuvwxyz"),
			expected: "abc\n\n",
		},
		{
			name:     "safe original split - CRLF",
			r:        strings.NewReader("a\r\n\r\nbcdefghijklmnop\n"),
			expected: "a\r\n\r\n",
		},
		// Current split is bad, look for a better one.
		{
			name:     "safe split - LF",
			r:        strings.NewReader("abcdefg\nhijklmnop\n\nqrstuvwxyz"),
			expected: "abcdefg\nhijklmnop\n\n",
		},
		{
			name:     "safe split - CRLF",
			r:        strings.NewReader("abcdefg\r\nhijklmnop\r\n\r\nqrstuvwxyz"),
			expected: "abcdefg\r\nhijklmnop\r\n\r\n",
		},
		{
			name:     "safe split - blank line",
			r:        strings.NewReader("abcdefg\nhijklmnop\n\t  \t\nqrstuvwxyz"),
			expected: "abcdefg\nhijklmnop\n\t  \t\n",
		},
		// Current split is bad, exhaust options.
		{
			name:     "no safe split",
			r:        strings.NewReader("abcdefg\nhijklmnopqrstuvwxyz"),
			expected: "abcdefg\nhijklmnopqrstuvwx",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, 5)
			n, err := c.r.Read(buf)
			require.NoError(t, err)

			// Act
			reader := bufio.NewReader(c.r)
			peekBuf := bytes.NewBuffer(buf[:n])
			err = readUntilSafeBoundary(reader, n, 20, peekBuf)
			require.NoError(t, err)

			// Assert
			t.Log(peekBuf.String())
			require.Equal(t, c.expected, peekBuf.String())
		})
	}
}

func TestPathEncodingRoundtrip(t *testing.T) {
	cases := []struct {
		name     string
		segments []string
	}{
		{
			name:     "single segment",
			segments: []string{"a/b.go"},
		},
		{
			name:     "nested",
			segments: []string{"outer.zip", "dir/inner.go"},
		},
		{
			name:     "spaces and exclamation",
			segments: []string{"a b.zip", "x!y.go"},
		},
		{
			name:     "literal backslash",
			segments: []string{"a.zip", `x\y.go`},
		},
		{
			name:     "combined specials across depths",
			segments: []string{"o!u.zip", `a\b/c!d.go`, "deep file.go"},
		},
		{
			name:     "escape and separator adjacent",
			segments: []string{"a.zip", `x\!y.go`, `x\\y.go`},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			encoded := make([]string, len(c.segments))
			for i, s := range c.segments {
				encoded[i] = encodePathSegment(s)
			}
			full := strings.Join(encoded, InnerPathSeparator)

			got := SplitFullPath(full)
			require.Equal(t, c.segments, got)
		})
	}
}

func TestSplitFullPath(t *testing.T) {
	cases := []struct {
		name     string
		full     string
		expected []string
	}{
		{
			name:     "plain",
			full:     "a.go",
			expected: []string{"a.go"},
		},
		{
			name:     "escaped exclamation",
			full:     `a.zip!x\!y.go`,
			expected: []string{"a.zip", "x!y.go"},
		},
		{
			name:     "escaped backslash",
			full:     `a.zip!x\\y.go`,
			expected: []string{"a.zip", `x\y.go`},
		},
		{
			name:     "multi depth",
			full:     "a.zip!b.tar!c.go",
			expected: []string{"a.zip", "b.tar", "c.go"},
		},
		{
			name:     "space preserved",
			full:     `my dir/a.zip!my file.go`,
			expected: []string{"my dir/a.zip", "my file.go"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.expected, SplitFullPath(c.full))
		})
	}
}

func TestArchiveStateConcurrency(t *testing.T) {
	st := newArchiveState(&ArchiveLimits{MaxEntries: 100})

	const goroutines = 100
	const perGoroutine = 10

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				st.entries.Add(1)
				st.addBytes(1)
			}
		}()
	}
	wg.Wait()

	require.Equal(t, int64(goroutines*perGoroutine), st.entries.Load())
	require.Equal(t, int64(goroutines*perGoroutine), st.totalBytes.Load())

	// The limit fires exactly once even under concurrent triggers.
	var (
		triggerWg sync.WaitGroup
		fired     int64
		mu        sync.Mutex
	)
	for i := 0; i < goroutines; i++ {
		triggerWg.Add(1)
		go func() {
			defer triggerWg.Done()
			if st.trigger("test limit") {
				mu.Lock()
				fired++
				mu.Unlock()
			}
		}()
	}
	triggerWg.Wait()

	require.Equal(t, int64(1), fired)
	require.True(t, st.triggered())
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// TestCountingReaderPartialError verifies bytes read before a read error are
// still counted, as when an archive ends midway through extraction.
func TestCountingReaderPartialError(t *testing.T) {
	var counted int64
	reader := countingReader{
		reader: io.MultiReader(strings.NewReader("hello"), failingReader{}),
		add: func(n int64) int64 {
			counted += n
			return counted
		},
	}

	_, err := io.ReadAll(reader)
	require.Error(t, err)
	require.Equal(t, int64(5), counted)
}
