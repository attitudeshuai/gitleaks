package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect/codec"
)

func condition(target config.EntropyTarget, threshold float64) *config.EntropyCondition {
	return &config.EntropyCondition{Index: 1, Target: target, Threshold: threshold}
}

func ruleWithConditions(conditions ...*config.EntropyCondition) config.Rule {
	for i, c := range conditions {
		c.Index = i + 1
	}
	return config.Rule{
		RuleID:   "test-rule",
		Strategy: &config.Strategy{Conditions: conditions},
	}
}

func TestEvaluateEntropyConditions(t *testing.T) {
	groups := []string{"key=abcdefghij1234567890", "abcdefghij1234567890"}

	t.Run("match target passes", func(t *testing.T) {
		r := ruleWithConditions(condition(config.EntropyTargetMatch, 3.0))
		ok, tags, c, reason, _, _ := evaluateEntropyConditions(r, groups[0], groups, nil, "")
		assert.True(t, ok)
		assert.Nil(t, c)
		assert.Equal(t, []string{"entropy-cond:1:match"}, tags)
		assert.Empty(t, reason)
	})

	t.Run("match target below threshold fails", func(t *testing.T) {
		lowEntropy := "abcabcabcabcabcabc"
		r := ruleWithConditions(condition(config.EntropyTargetMatch, 3.0))
		ok, _, c, reason, value, ent := evaluateEntropyConditions(r, lowEntropy, []string{lowEntropy}, nil, "")
		assert.False(t, ok)
		require.NotNil(t, c)
		assert.Equal(t, "entropy below threshold", reason)
		assert.Equal(t, lowEntropy, value)
		assert.Greater(t, ent, 0.0)
	})

	t.Run("existing group passes", func(t *testing.T) {
		c := condition(config.EntropyTargetGroup, 3.0)
		c.Group = 1
		r := ruleWithConditions(c)
		ok, tags, failed, _, _, _ := evaluateEntropyConditions(r, groups[0], groups, nil, "")
		assert.True(t, ok)
		assert.Nil(t, failed)
		assert.Equal(t, []string{"entropy-cond:1:group"}, tags)
	})

	t.Run("missing group is not satisfied without panicking", func(t *testing.T) {
		c := condition(config.EntropyTargetGroup, 3.0)
		c.Group = 5
		r := ruleWithConditions(c)
		ok, _, failed, reason, value, _ := evaluateEntropyConditions(r, groups[0], groups, nil, "")
		assert.False(t, ok)
		require.NotNil(t, failed)
		assert.Equal(t, "capture group does not exist for this match", reason)
		assert.Empty(t, value)
	})

	t.Run("group that did not participate is not satisfied", func(t *testing.T) {
		c := condition(config.EntropyTargetGroup, 3.0)
		c.Group = 2
		r := ruleWithConditions(c)
		// groups[2] exists but is empty (optional group did not match)
		ok, _, failed, reason, _, _ := evaluateEntropyConditions(r, groups[0], []string{groups[0], groups[1], ""}, nil, "")
		assert.False(t, ok)
		require.NotNil(t, failed)
		assert.Equal(t, "capture group did not participate in the match", reason)
	})

	t.Run("decoded target on the raw pass is not satisfied", func(t *testing.T) {
		r := ruleWithConditions(condition(config.EntropyTargetDecoded, 3.0))
		ok, _, failed, reason, _, _ := evaluateEntropyConditions(r, groups[0], groups, nil, "")
		assert.False(t, ok)
		require.NotNil(t, failed)
		assert.Equal(t, "no decoded content in this decoding pass", reason)
	})

	t.Run("decoded target with no overlap is not satisfied", func(t *testing.T) {
		r := ruleWithConditions(condition(config.EntropyTargetDecoded, 3.0))
		decoder := codec.NewDecoder(codec.Base64Kind)
		raw := "token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q="
		out, segments := decoder.Decode(raw, nil)
		// A range entirely before the decoded segment.
		ok, _, failed, reason, _, _ := evaluateEntropyConditions(r, "token:", []string{"token:"}, segments, codec.DecodedValue(segments, out, 0, 6))
		assert.False(t, ok)
		require.NotNil(t, failed)
		assert.Equal(t, "match does not overlap a decoded value", reason)
	})

	t.Run("decoded target passes on the decoded value", func(t *testing.T) {
		r := ruleWithConditions(condition(config.EntropyTargetDecoded, 3.0))
		decoder := codec.NewDecoder(codec.Base64Kind)
		raw := "token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q="
		out, segments := decoder.Decode(raw, nil)
		decoded := codec.DecodedValue(segments, out, 7, len(out))
		require.NotEmpty(t, decoded)
		ok, tags, failed, _, _, _ := evaluateEntropyConditions(r, out, nil, segments, decoded)
		assert.True(t, ok)
		assert.Nil(t, failed)
		assert.Equal(t, []string{"entropy-cond:1:decoded"}, tags)
	})

	t.Run("length constraints", func(t *testing.T) {
		long := condition(config.EntropyTargetMatch, 0.1)
		long.MinLength = 100
		r := ruleWithConditions(long)
		ok, _, failed, reason, value, _ := evaluateEntropyConditions(r, groups[0], groups, nil, "")
		assert.False(t, ok)
		require.NotNil(t, failed)
		assert.Equal(t, "value shorter than minLength", reason)
		assert.Equal(t, groups[0], value)

		short := condition(config.EntropyTargetMatch, 0.1)
		short.MaxLength = 5
		r = ruleWithConditions(short)
		ok, _, failed, reason, _, _ = evaluateEntropyConditions(r, groups[0], groups, nil, "")
		assert.False(t, ok)
		require.NotNil(t, failed)
		assert.Equal(t, "value longer than maxLength", reason)
	})

	t.Run("conditions short circuit in declaration order", func(t *testing.T) {
		lowEntropy := "abcabcabcabcabcabc"
		first := condition(config.EntropyTargetMatch, 3.0) // fails (low entropy)
		second := condition(config.EntropyTargetDecoded, 0.1)
		r := ruleWithConditions(first, second)
		ok, tags, failed, reason, _, _ := evaluateEntropyConditions(r, lowEntropy, []string{lowEntropy}, nil, "")
		assert.False(t, ok)
		require.NotNil(t, failed)
		assert.Equal(t, 1, failed.Index)
		assert.Equal(t, "entropy below threshold", reason)
		assert.Empty(t, tags)
	})
}
