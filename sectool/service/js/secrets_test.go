package js

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractSecrets(t *testing.T) {
	t.Parallel()

	t.Run("matched_literal_kinds", func(t *testing.T) {
		cases := []struct {
			name     string
			literal  string
			wantKind string
		}{
			{"aws_access_key", "AKIAIOSFODNN7EXAMPLE", "aws_access_key"},
			{"github_pat", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github_pat"},
			{"github_oauth", "gho_abcdefghijklmnopqrstuvwxyz0123456789", "github_oauth"},
			{"github_fine_grained", "github_pat_11ABCDEFG0abcdefghijkl_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVW", "github_fine_grained"},
			{"google_api_key", "AIzaSyA-1234567890abcdefghijklmnopqrstu", "google_api_key"},
			{"openai_api_key", "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV", "openai_api_key"},
			{"openai_proj_key", "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV", "openai_proj_key"},
			{"anthropic_api_key", "sk-ant-api03-" + strings.Repeat("a", 95), "anthropic_api_key"},
			{"stripe_live_key", "sk_live_" + strings.Repeat("a", 30), "stripe_live_key"},
			{"stripe_publishable_key", "pk_live_" + strings.Repeat("a", 30), "stripe_publishable_key"},
			{"sentry_dsn", "https://abcdef0123456789abcdef0123456789@sentry.example.com/1234", "sentry_dsn"},
			{"digitalocean_token", "dop_v1_" + strings.Repeat("a", 64), "digitalocean_token"},
			{"shopify_access_token", "shpat_" + strings.Repeat("a", 32), "shopify_access_token"},
			{"sendgrid_api_key", "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43), "sendgrid_api_key"},
			{"vault_service_token", "hvs." + strings.Repeat("a", 30), "vault_service_token"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := extractSecrets(nil, []string{tc.literal})
				assert.Len(t, got, 1)
				assert.Equal(t, tc.wantKind, got[0].Kind)
				assert.Equal(t, tc.literal, got[0].Value)
			})
		}
	})

	t.Run("non_secret_rejected", func(t *testing.T) {
		negatives := []string{
			"AKIA_TOO_SHORT",
			"AKIA123",
			"sk-tooShort",
			"ghp_short",
			"https://example.com/regular/path",
			"hello world",
			"Bearer abc",
			strings.Repeat("A", 40),
		}
		got := extractSecrets(nil, negatives)
		assert.Empty(t, got)
	})

	t.Run("pem_in_body", func(t *testing.T) {
		body := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
-----END RSA PRIVATE KEY-----`)
		got := extractSecrets(body, nil)
		assert.Len(t, got, 1)
		assert.Equal(t, "private_key", got[0].Kind)
	})

	t.Run("no_dedupe_within_pass", func(t *testing.T) {
		// One record per matched literal; collapsing duplicates is dedupeSecrets's job.
		lit := "AKIAIOSFODNN7EXAMPLE"
		got := extractSecrets(nil, []string{lit, lit})
		assert.Len(t, got, 2)
	})
}
