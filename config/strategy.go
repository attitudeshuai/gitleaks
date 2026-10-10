package config

import (
	"fmt"
	"strings"

	"github.com/zricethezav/gitleaks/v8/detect/codec"
)

// EntropyTarget identifies what an entropy condition is evaluated against.
type EntropyTarget int

const (
	// EntropyTargetMatch evaluates the condition against the entire regex
	// match.
	EntropyTargetMatch EntropyTarget = iota
	// EntropyTargetGroup evaluates the condition against a specific regex
	// capture group (see EntropyCondition.Group).
	EntropyTargetGroup
	// EntropyTargetDecoded evaluates the condition against the value
	// produced by decoding the match.
	EntropyTargetDecoded
)

// String returns the TOML name of the target.
func (t EntropyTarget) String() string {
	switch t {
	case EntropyTargetMatch:
		return "match"
	case EntropyTargetGroup:
		return "group"
	case EntropyTargetDecoded:
		return "decoded"
	default:
		return "unknown"
	}
}

// parseEntropyTarget parses the |target| value of an entropy condition.
func parseEntropyTarget(target string) (EntropyTarget, error) {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "", "match":
		return EntropyTargetMatch, nil
	case "group":
		return EntropyTargetGroup, nil
	case "decoded":
		return EntropyTargetDecoded, nil
	default:
		return 0, fmt.Errorf("unknown entropy condition |target| %q (expected 'match', 'group', or 'decoded')", target)
	}
}

// charsetPresets are named character sets that can be referenced from an
// entropy condition's |charset| field. Any other (non-empty) value is treated
// as the literal set of allowed characters.
var charsetPresets = map[string]string{
	"numeric":      "0123456789",
	"hex":          "0123456789abcdefABCDEF",
	"alphanumeric": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"base64":       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
	"base64url":    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=",
}

// EntropyCondition is a single entropy judgment that a match must satisfy.
type EntropyCondition struct {
	// Index is the 1-based position of the condition in the rule's
	// declaration, used in logs and finding tags.
	Index int

	// Target is what the condition is evaluated against.
	Target EntropyTarget

	// Group is the 1-based regex capture group used when Target is
	// EntropyTargetGroup.
	Group int

	// Threshold is the minimum (exclusive) shannon entropy the target must
	// have.
	Threshold float64

	// MinLength/MaxLength optionally constrain the length (in bytes) of the
	// target value. A zero value disables the constraint.
	MinLength int
	MaxLength int

	// Charset optionally restricts every character of the target value to
	// this set of characters. An empty string disables the constraint.
	Charset string

	// charsetRunes is Charset resolved into a lookup set once at config
	// load time. nil means no charset constraint is configured.
	charsetRunes map[rune]struct{}
}

// AllowsCharset reports whether every rune in |value| belongs to the
// condition's charset. When no charset is configured any value is allowed.
func (c *EntropyCondition) AllowsCharset(value string) bool {
	if len(c.charsetRunes) == 0 {
		return true
	}
	for _, r := range value {
		if _, ok := c.charsetRunes[r]; !ok {
			return false
		}
	}
	return true
}

// Strategy is a rule-level decoding and judgment policy. A nil *Strategy
// means the rule keeps the historical behavior: participate in every global
// decoding pass and use the rule's single Entropy threshold.
type Strategy struct {
	// EnabledEncodings is the subset of encodings whose decode passes the
	// rule participates in.
	EnabledEncodings codec.EncodingKind

	// EncodingsDeclared reports whether the rule explicitly declared its
	// encoding participation. When false the rule participates in every
	// encoding (even though EnabledEncodings holds all kinds).
	EncodingsDeclared bool

	// MaxDepth is the rule-specific cap on decoding passes. Zero means the
	// global max-decode-depth is the only cap. It is always bounded by the
	// global max-decode-depth.
	MaxDepth int

	// MinDecodedLength is the minimum length of a match's decoded value for
	// the match to be accepted on a decoding pass. Zero disables the check.
	MinDecodedLength int

	// Conditions are the entropy conditions evaluated against each match,
	// in declaration order. When present they replace the rule's legacy
	// Entropy threshold check.
	Conditions []*EntropyCondition
}

// viperDecoding is the on-disk representation of [rules.decoding].
type viperDecoding struct {
	// Encodings lists the encodings the rule participates in. A nil slice
	// means "all encodings" while an explicit empty slice means the rule is
	// never matched against decoded text.
	Encodings []string
	// MaxDepth caps how many decoding passes the rule is re-matched on.
	MaxDepth int `mapstructure:"maxDepth"`
	// MinLength is the minimum acceptable decoded value length.
	MinLength int `mapstructure:"minLength"`
}

// viperEntropyCondition is the on-disk representation of an entry in
// [[rules.entropy_conditions]].
type viperEntropyCondition struct {
	Target    string
	Group     int
	Threshold float64
	MinLength int `mapstructure:"minLength"`
	MaxLength int `mapstructure:"maxLength"`
	Charset   string
}

// parseStrategy converts the on-disk decoding/entropy configuration into the
// parsed *Strategy. It returns (nil, nil) when the rule did not declare any
// policy, which preserves the historical rule behavior.
func parseStrategy(vd *viperDecoding, vc []*viperEntropyCondition) (*Strategy, error) {
	if vd == nil && len(vc) == 0 {
		return nil, nil
	}

	s := &Strategy{}

	if vd != nil {
		if vd.Encodings != nil {
			kinds, err := codec.ParseEncodingKinds(vd.Encodings)
			if err != nil {
				return nil, err
			}
			s.EnabledEncodings = kinds
			s.EncodingsDeclared = true
		} else {
			s.EnabledEncodings = codec.AllEncodingKinds
		}
		s.MaxDepth = vd.MaxDepth
		s.MinDecodedLength = vd.MinLength
	} else {
		s.EnabledEncodings = codec.AllEncodingKinds
	}

	for i, condition := range vc {
		target, err := parseEntropyTarget(condition.Target)
		if err != nil {
			return nil, err
		}

		charset := ""
		var charsetRunes map[rune]struct{}
		if condition.Charset != "" {
			if preset, ok := charsetPresets[condition.Charset]; ok {
				charset = preset
			} else {
				// The literal value is the set of allowed characters.
				charset = condition.Charset
			}
			charsetRunes = make(map[rune]struct{})
			for _, r := range charset {
				charsetRunes[r] = struct{}{}
			}
		}

		s.Conditions = append(s.Conditions, &EntropyCondition{
			Index:        i + 1,
			Target:       target,
			Group:        condition.Group,
			Threshold:    condition.Threshold,
			MinLength:    condition.MinLength,
			MaxLength:    condition.MaxLength,
			Charset:      charset,
			charsetRunes: charsetRunes,
		})
	}

	return s, nil
}

// validateStrategy performs load-time validation of the rule's strategy. It
// enforces value ranges and rejects conditions that contradict each other or
// the rest of the rule.
func (r *Rule) validateStrategy() error {
	s := r.Strategy
	if s == nil {
		return nil
	}

	if s.MaxDepth < 0 {
		return fmt.Errorf("%s: |decoding.maxDepth| must be greater than or equal to 0", r.RuleID)
	}
	if s.MinDecodedLength < 0 {
		return fmt.Errorf("%s: |decoding.minLength| must be greater than or equal to 0", r.RuleID)
	}
	if s.EncodingsDeclared && s.EnabledEncodings == 0 && r.Regex == nil {
		return fmt.Errorf("%s: |decoding.encodings| is empty on a rule without |regex|, the rule can never match decoded text", r.RuleID)
	}
	if r.Entropy != 0.0 && len(s.Conditions) > 0 {
		return fmt.Errorf("%s: |entropy| cannot be combined with [[rules.entropy_conditions]], remove one of them", r.RuleID)
	}

	for _, c := range s.Conditions {
		if c.Threshold <= 0.0 {
			return fmt.Errorf("%s: entropy condition #%d has an invalid |threshold| %v, it must be greater than 0", r.RuleID, c.Index, c.Threshold)
		}
		if c.MinLength < 0 {
			return fmt.Errorf("%s: entropy condition #%d has a negative |minLength|", r.RuleID, c.Index)
		}
		if c.MaxLength < 0 {
			return fmt.Errorf("%s: entropy condition #%d has a negative |maxLength|", r.RuleID, c.Index)
		}
		if c.MinLength > 0 && c.MaxLength > 0 && c.MinLength > c.MaxLength {
			return fmt.Errorf("%s: entropy condition #%d is contradictory, |minLength| %d is greater than |maxLength| %d", r.RuleID, c.Index, c.MinLength, c.MaxLength)
		}

		switch c.Target {
		case EntropyTargetGroup:
			if r.Regex == nil {
				return fmt.Errorf("%s: entropy condition #%d targets a capture group but the rule has no |regex|", r.RuleID, c.Index)
			}
			if c.Group < 1 {
				return fmt.Errorf("%s: entropy condition #%d targets a capture group but does not specify a valid |group| (must be >= 1)", r.RuleID, c.Index)
			}
			if c.Group > r.Regex.NumSubexp() {
				return fmt.Errorf("%s: entropy condition #%d references capture group %d but the regex only has %d group(s)", r.RuleID, c.Index, c.Group, r.Regex.NumSubexp())
			}
		case EntropyTargetDecoded:
			if s.EncodingsDeclared && s.EnabledEncodings == 0 {
				return fmt.Errorf("%s: entropy condition #%d targets the decoded value but |decoding.encodings| is empty, the condition can never be satisfied", r.RuleID, c.Index)
			}
		}
	}

	return nil
}
