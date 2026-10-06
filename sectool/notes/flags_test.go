package notes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()

	t.Run("subcommand_required", func(t *testing.T) {
		err := Parse(nil, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subcommand required")
	})

	t.Run("unknown_subcommand", func(t *testing.T) {
		err := Parse([]string{"bogus"}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown notes subcommand")
	})

	t.Run("get_requires_note_id", func(t *testing.T) {
		err := Parse([]string{"get"}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "note_id required")
	})

	t.Run("delete_requires_note_id", func(t *testing.T) {
		err := Parse([]string{"delete"}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "note_id required")
	})

	t.Run("help", func(t *testing.T) {
		assert.NoError(t, Parse([]string{"help"}, ""))
		assert.NoError(t, Parse([]string{"--help"}, ""))
	})
}

func TestParseIDList(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", []string{}},
		{"single", "abc", []string{"abc"}},
		{"multiple", "abc,def", []string{"abc", "def"}},
		{"drops_empties", "abc,,def,", []string{"abc", "def"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseIDList(tc.in))
		})
	}
}
