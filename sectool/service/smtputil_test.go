package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractEmailTo(t *testing.T) {
	t.Parallel()

	t.Run("single_address", func(t *testing.T) {
		headers := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: test"
		got := extractEmailTo(headers)
		assert.Equal(t, []string{"recipient@example.com"}, got)
	})

	t.Run("angle_bracket_address", func(t *testing.T) {
		headers := "From: sender@example.com\r\nTo: \"Recipient Name\" <recipient@example.com>\r\nSubject: test"
		got := extractEmailTo(headers)
		assert.Equal(t, []string{"recipient@example.com"}, got)
	})

	t.Run("multiple_addresses", func(t *testing.T) {
		headers := "To: alice@example.com, Bob <bob@example.com>\r\nSubject: test"
		got := extractEmailTo(headers)
		assert.Equal(t, []string{"alice@example.com", "bob@example.com"}, got)
	})

	t.Run("folded_header", func(t *testing.T) {
		headers := "To: \"Recipient\" <recipient@example.com>,\r\n second@example.com\r\nSubject: test"
		got := extractEmailTo(headers)
		assert.Equal(t, []string{"recipient@example.com", "second@example.com"}, got)
	})

	t.Run("bare_lf", func(t *testing.T) {
		headers := "From: sender@example.com\nTo: recipient@example.com\nSubject: test"
		got := extractEmailTo(headers)
		assert.Equal(t, []string{"recipient@example.com"}, got)
	})

	t.Run("no_to_header", func(t *testing.T) {
		headers := "From: sender@example.com\r\nSubject: test"
		got := extractEmailTo(headers)
		assert.Nil(t, got)
	})

	t.Run("case_insensitive", func(t *testing.T) {
		headers := "TO: recipient@example.com\r\nSubject: test"
		got := extractEmailTo(headers)
		assert.Equal(t, []string{"recipient@example.com"}, got)
	})

	t.Run("empty_headers", func(t *testing.T) {
		got := extractEmailTo("")
		assert.Nil(t, got)
	})
}
