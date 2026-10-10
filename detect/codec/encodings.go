package codec

import (
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

// EncodingKind is exported so other packages (e.g. config) can reference the
// supported encoding types. encodingKind can be or'd together to capture all
// of the unique encodings that were present in a segment.
type EncodingKind = encodingKind

var (
	// encodings contains all the encoding configurations for the detector.
	// The precedence is important. You want more specific encodings to
	// have a higher precedence or encodings that partially encode the
	// values (e.g. percent) unlike encodings that fully encode the string
	// (e.g. base64). If two encoding matches overlap the decoder will use
	// this order to determine which encoding should wait till the next pass.
	encodings = []*encoding{
		{
			kind:    percentKind,
			pattern: `%[0-9A-Fa-f]{2}(?:.*%[0-9A-Fa-f]{2})?`,
			decode:  decodePercent,
		},
		{
			kind:    unicodeKind,
			pattern: `(?:(?:U\+[a-fA-F0-9]{4}(?:\s|$))+|(?i)(?:\\{1,2}u[a-fA-F0-9]{4})+)`,
			decode:  decodeUnicode,
		},
		{
			kind:    hexKind,
			pattern: `[0-9A-Fa-f]{32,}`,
			decode:  decodeHex,
		},
		{
			kind:    base64Kind,
			pattern: `[\w\/+-]{16,}={0,2}`,
			decode:  decodeBase64,
		},
	}

	// encodingNames is used to map the encodingKinds to their name
	encodingNames = []string{
		"percent",
		"unicode",
		"hex",
		"base64",
	}
)

// Exported encoding kinds so callers can construct decoders limited to a
// subset of the supported encodings.
const (
	PercentKind = encodingKind(1)
	UnicodeKind = encodingKind(2)
	HexKind     = encodingKind(4)
	Base64Kind  = encodingKind(8)
)

// AllEncodingKinds or's together every supported encoding kind.
const AllEncodingKinds = PercentKind | UnicodeKind | HexKind | Base64Kind

// encodingKind can be or'd together to capture all of the unique encodings
// that were present in a segment
type encodingKind int

var (
	// make sure these go up by powers of 2
	percentKind = PercentKind
	unicodeKind = UnicodeKind
	hexKind     = HexKind
	base64Kind  = Base64Kind
)

func (e encodingKind) String() string {
	i := int(math.Log2(float64(e)))
	if i >= len(encodingNames) {
		return ""
	}
	return encodingNames[i]
}

// kinds returns a list of encodingKinds combined in this one
func (e encodingKind) kinds() []encodingKind {
	kinds := []encodingKind{}

	for i := 0; i < len(encodingNames); i++ {
		if kind := int(e) & int(math.Pow(2, float64(i))); kind != 0 {
			kinds = append(kinds, encodingKind(kind))
		}
	}

	return kinds
}

// ParseEncodingKinds converts a list of encoding names (e.g. "base64") into
// an or'd together encodingKind. Names are case-insensitive.
func ParseEncodingKinds(names []string) (encodingKind, error) {
	var kinds encodingKind
	for _, name := range names {
		var found encodingKind
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "percent":
			found = PercentKind
		case "unicode":
			found = UnicodeKind
		case "hex":
			found = HexKind
		case "base64":
			found = Base64Kind
		default:
			return 0, fmt.Errorf("unknown encoding %q (expected one of: %s)", name, strings.Join(encodingNames, ", "))
		}
		kinds |= found
	}
	return kinds, nil
}

// encodingMatch represents a match of an encoding in the text
type encodingMatch struct {
	encoding *encoding
	startEnd
}

// encoding represent a type of coding supported by the decoder.
type encoding struct {
	// the kind of decoding (e.g. base64, etc)
	kind encodingKind
	// the regex pattern that matches the encoding format
	pattern string
	// take the match and return the decoded value
	decode func(string) string
	// determine which encoding should win out when two overlap
	precedence int
}

var (
	// encodingReses caches the combined encoding regex for each subset of
	// encoding kinds. The all-kinds entry is populated up front by init for
	// backwards compatibility.
	encodingReses = map[encodingKind]*regexp.Regexp{
		AllEncodingKinds: nil,
	}
	encodingResesMu sync.Mutex
)

func init() {
	// Assign precedence based on the position in the global |encodings|
	// slice so that a subset of encodings keeps the exact same relative
	// precedence as the full set.
	count := len(encodings)
	for i, encoding := range encodings {
		encoding.precedence = count - i
	}
	encodingReses[AllEncodingKinds] = buildEncodingsRe(AllEncodingKinds)
}

// buildEncodingsRe combines the patterns of the encodings contained in |mask|
// into named capture groups so a single regex pass can detect each of them.
// The relative precedence of the encodings is identical regardless of which
// subset is selected.
func buildEncodingsRe(mask encodingKind) *regexp.Regexp {
	namedPatterns := make([]string, 0, len(encodings))
	for _, encoding := range encodings {
		if mask&encoding.kind == 0 {
			continue
		}
		namedPatterns = append(namedPatterns, fmt.Sprintf(
			"(?P<%s>%s)",
			encoding.kind,
			encoding.pattern,
		))
	}
	return regexp.MustCompile(strings.Join(namedPatterns, "|"))
}

// encodingsReFor returns the cached combined regex for the given subset of
// encoding kinds, building it on first use.
func encodingsReFor(mask encodingKind) *regexp.Regexp {
	encodingResesMu.Lock()
	defer encodingResesMu.Unlock()
	if re, ok := encodingReses[mask]; ok {
		return re
	}
	re := buildEncodingsRe(mask)
	encodingReses[mask] = re
	return re
}

// findEncodingMatches finds as many encodings enabled by |mask| as it can for
// this pass
func findEncodingMatches(data string, mask encodingKind) []encodingMatch {
	var all []encodingMatch
	enabled := make([]*encoding, 0, len(encodings))
	for _, encoding := range encodings {
		if mask&encoding.kind != 0 {
			enabled = append(enabled, encoding)
		}
	}

	for _, matchIndex := range encodingsReFor(mask).FindAllStringSubmatchIndex(data, -1) {
		// Add the encodingMatch with its proper encoding
		for i, j := 2, 0; i < len(matchIndex); i, j = i+2, j+1 {
			if matchIndex[i] > -1 {
				all = append(all, encodingMatch{
					encoding: enabled[j],
					startEnd: startEnd{
						start: matchIndex[i],
						end:   matchIndex[i+1],
					},
				})
			}
		}
	}

	totalMatches := len(all)
	if totalMatches == 1 {
		return all
	}

	// filter out lower precedence ones that overlap their neigbors
	filtered := make([]encodingMatch, 0, len(all))
	for i, m := range all {
		if i > 0 {
			prev := all[i-1]
			if m.overlaps(prev.startEnd) && prev.encoding.precedence > m.encoding.precedence {
				continue // skip this one
			}
		}
		if i+1 < totalMatches {
			next := all[i+1]
			if m.overlaps(next.startEnd) && next.encoding.precedence > m.encoding.precedence {
				continue // skip this one
			}
		}
		filtered = append(filtered, m)
	}

	return filtered
}
