package codec

import (
	"encoding/hex"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		chunk    string
		expected string
		name     string
	}{
		{
			name:     "only b64 chunk",
			chunk:    `bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`,
			expected: `longer-encoded-secret-test`,
		},
		{
			name:     "mixed content",
			chunk:    `token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`,
			expected: `token: longer-encoded-secret-test`,
		},
		{
			name:     "no chunk",
			chunk:    ``,
			expected: ``,
		},
		{
			name:     "env var (looks like all b64 decodable but has `=` in the middle)",
			chunk:    `some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=`,
			expected: `some-encoded-secret=test-secret-value`,
		},
		{
			name:     "has longer b64 inside",
			chunk:    `some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q="`,
			expected: `some-encoded-secret="longer-encoded-secret-test"`,
		},
		{
			name: "many possible i := 0substrings",
			chunk: `Many substrings in this slack message could be base64 decoded
				but only dGhpcyBlbmNhcHN1bGF0ZWQgc2VjcmV0 should be decoded.`,
			expected: `Many substrings in this slack message could be base64 decoded
				but only this encapsulated secret should be decoded.`,
		},
		{
			name:     "b64-url-safe: only b64 chunk",
			chunk:    `bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q`,
			expected: `longer-encoded-secret-test`,
		},
		{
			name:     "b64-url-safe: mixed content",
			chunk:    `token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q`,
			expected: `token: longer-encoded-secret-test`,
		},
		{
			name:     "b64-url-safe: env var (looks like all b64 decodable but has `=` in the middle)",
			chunk:    `some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=`,
			expected: `some-encoded-secret=test-secret-value`,
		},
		{
			name:     "b64-url-safe: has longer b64 inside",
			chunk:    `some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q"`,
			expected: `some-encoded-secret="longer-encoded-secret-test"`,
		},
		{
			name:     "b64-url-safe: hyphen url b64",
			chunk:    `Z2l0bGVha3M-PmZpbmRzLXNlY3JldHM`,
			expected: `gitleaks>>finds-secrets`,
		},
		{
			name:     "b64-url-safe: underscore url b64",
			chunk:    `YjY0dXJsc2FmZS10ZXN0LXNlY3JldC11bmRlcnNjb3Jlcz8_`,
			expected: `b64urlsafe-test-secret-underscores??`,
		},
		{
			name:     "invalid base64 string",
			chunk:    `a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3`,
			expected: `a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3`,
		},
		{
			name:     "url encoded value",
			chunk:    `secret%3D%22q%24%21%40%23%24%25%5E%26%2A%28%20asdf%22`,
			expected: `secret="q$!@#$%^&*( asdf"`,
		},
		{
			name:     "hex encoded value",
			chunk:    `secret="466973684D617048756E6B79212121363334"`,
			expected: `secret="FishMapHunky!!!634"`,
		},
		{
			name:     "unicode encoded value",
			chunk:    `secret=U+0061 U+0062 U+0063 U+0064 U+0065 U+0066`,
			expected: "secret=abcdef",
		},
		{
			name:     "unicode encoded value backslashed",
			chunk:    `secret=\\u0068\\u0065\\u006c\\u006c\\u006f\\u0020\\u0077\\u006f\\u0072\\u006c\\u0064\\u0020\\u0064\\u0075\\u0064\\u0065`,
			expected: "secret=hello world dude",
		},
		{
			name:     "unicode encoded value backslashed mixed w/ hex",
			chunk:    `secret=\u0068\u0065\u006c\u006c\u006f\u0020\u0077\u006f\u0072\u006c\u0064 6C6F76656C792070656F706C65206F66206561727468`,
			expected: "secret=hello world lovely people of earth",
		},
	}

	decoder := NewDecoder()
	fullDecode := func(data string) string {
		segments := []*EncodedSegment{}
		for {
			data, segments = decoder.Decode(data, segments)
			if len(segments) == 0 {
				return data
			}
		}
	}

	// Test value decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, fullDecode(tt.chunk))
		})
	}

	// Percent encode the values to test percent decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodedChunk := url.PathEscape(tt.chunk)
			assert.Equal(t, tt.expected, fullDecode(encodedChunk))
		})
	}

	// Hex encode the values to test hex decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodedChunk := hex.EncodeToString([]byte(tt.chunk))
			assert.Equal(t, tt.expected, fullDecode(encodedChunk))
		})
	}
}

// TestDecoderEncodingSubsets verifies that a decoder limited to a subset of
// encodings only decodes the segments of those encodings.
func TestDecoderEncodingSubsets(t *testing.T) {
	// A percent encoded and a base64 encoded value on the same line.
	chunk := `secret=%3D bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`

	t.Run("percent only", func(t *testing.T) {
		decoder := NewDecoder(PercentKind)
		assert.Equal(t, PercentKind, decoder.Kinds())
		out, segments := decoder.Decode(chunk, nil)
		require.Len(t, segments, 1)
		assert.Equal(t, PercentKind, segments[0].encodings)
		assert.Equal(t, `secret== bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`, out)
	})

	t.Run("base64 only", func(t *testing.T) {
		decoder := NewDecoder(Base64Kind)
		assert.Equal(t, Base64Kind, decoder.Kinds())
		out, segments := decoder.Decode(chunk, nil)
		require.Len(t, segments, 1)
		assert.Equal(t, Base64Kind, segments[0].encodings)
		assert.Equal(t, `secret=%3D longer-encoded-secret-test`, out)
	})

	t.Run("all by default", func(t *testing.T) {
		decoder := NewDecoder()
		assert.Equal(t, AllEncodingKinds, decoder.Kinds())
		out, segments := decoder.Decode(chunk, nil)
		require.Len(t, segments, 2)
		assert.Equal(t, `secret== longer-encoded-secret-test`, out)
	})
}

func TestParseEncodingKinds(t *testing.T) {
	kinds, err := ParseEncodingKinds([]string{"Base64", " hex "})
	require.NoError(t, err)
	assert.Equal(t, Base64Kind|HexKind, kinds)

	_, err = ParseEncodingKinds([]string{"rot13"})
	assert.ErrorContains(t, err, `unknown encoding "rot13"`)
}

func TestDecodedValue(t *testing.T) {
	decoder := NewDecoder()
	data := `token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`
	out, segments := decoder.Decode(data, nil)
	require.Len(t, segments, 1)

	// A range fully covering the decoded segment returns the whole value.
	assert.Equal(t, "longer-encoded-secret-test", DecodedValue(segments, out, 7, len(out)))
	// A partial range intersects the decoded value.
	assert.Equal(t, "longer", DecodedValue(segments, out, 7, 13))
	// A range outside the decoded content returns nothing.
	assert.Equal(t, "", DecodedValue(segments, out, 0, 7))
	// No segments returns nothing.
	assert.Equal(t, "", DecodedValue(nil, out, 0, len(out)))
}
