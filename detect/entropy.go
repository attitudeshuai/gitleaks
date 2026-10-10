package detect

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect/codec"
)

// entropyConditionTag is the tag appended to a finding for each entropy
// condition that was satisfied, e.g. "entropy-cond:1:group".
func entropyConditionTag(c *config.EntropyCondition) string {
	return fmt.Sprintf("entropy-cond:%d:%s", c.Index, c.Target)
}

// evaluateEntropyConditions evaluates the rule's declared entropy conditions
// in declaration order against a single match.
//
// It returns:
//   - ok: whether every condition was satisfied;
//   - tags: a tag per satisfied condition (only meaningful when ok is true);
//   - condition: the first condition that was not satisfied (nil when ok);
//   - reason: a machine-readable explanation of the failure;
//   - value: the target value considered by the failing condition;
//   - entropy: the shannon entropy computed for |value| (0 when not reached).
//
// Conditions that cannot be evaluated for the current pass (missing capture
// group, no decoded content, ...) are reported as not satisfied instead of
// aborting the scan.
func evaluateEntropyConditions(
	r config.Rule,
	matchText string,
	groups []string,
	overlapSegments []*codec.EncodedSegment,
	decodedValue string,
) (bool, []string, *config.EntropyCondition, string, string, float64) {
	var tags []string

	for _, c := range r.Strategy.Conditions {
		fail := func(reason, value string) (bool, []string, *config.EntropyCondition, string, string, float64) {
			return false, tags, c, reason, value, 0
		}

		var value string
		switch c.Target {
		case config.EntropyTargetMatch:
			value = matchText

		case config.EntropyTargetGroup:
			// Load-time validation bounds |c.Group| by the number of regex
			// groups, but guard defensively so a malformed match can never
			// panic the scanner.
			if c.Group >= len(groups) {
				return fail("capture group does not exist for this match", "")
			}
			value = groups[c.Group]
			if value == "" {
				return fail("capture group did not participate in the match", "")
			}

		case config.EntropyTargetDecoded:
			// On the raw (depth 0) pass there are no decoded segments; a
			// match overlapping no segment likewise has no decoded value.
			if len(overlapSegments) == 0 {
				return fail("no decoded content in this decoding pass", "")
			}
			value = decodedValue
			if value == "" {
				return fail("match does not overlap a decoded value", "")
			}
		}

		if c.MinLength > 0 && len(value) < c.MinLength {
			return fail("value shorter than minLength", value)
		}
		if c.MaxLength > 0 && len(value) > c.MaxLength {
			return fail("value longer than maxLength", value)
		}
		if !c.AllowsCharset(value) {
			return fail("value contains characters outside charset", value)
		}

		entropy := shannonEntropy(value)
		if entropy <= c.Threshold {
			// The caller logs the full context; return the entropy with the
			// failure so it is recorded as well.
			return false, tags, c, "entropy below threshold", value, entropy
		}

		tags = append(tags, entropyConditionTag(c))
	}

	return true, tags, nil, "", "", 0
}
