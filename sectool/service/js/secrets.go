package js

import (
	"regexp"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

// secretPattern pairs a credential kind label with an anchored regex.
// Patterns are intentionally narrow; generic base64/hex shapes are excluded
// because they produce too many false positives in minified bundles.
type secretPattern struct {
	kind string
	re   *regexp.Regexp
}

// literalSecretPatterns are matched against full string-literal values extracted from JS.
var literalSecretPatterns = []secretPattern{
	{"aws_access_key", regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`)},
	{"github_fine_grained", regexp.MustCompile(`^github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}$`)},
	{"github_pat", regexp.MustCompile(`^ghp_[a-zA-Z0-9]{36}$`)},
	{"github_oauth", regexp.MustCompile(`^gho_[a-zA-Z0-9]{36}$`)},
	{"github_user_token", regexp.MustCompile(`^ghu_[a-zA-Z0-9]{36}$`)},
	{"github_server_token", regexp.MustCompile(`^ghs_[a-zA-Z0-9]{36}$`)},
	{"github_refresh", regexp.MustCompile(`^ghr_[a-zA-Z0-9]{36}$`)},
	{"google_api_key", regexp.MustCompile(`^AIza[0-9A-Za-z\-_]{35}$`)},
	{"openai_proj_key", regexp.MustCompile(`^sk-proj-[a-zA-Z0-9]{48}$`)},
	{"openai_api_key", regexp.MustCompile(`^sk-[a-zA-Z0-9]{48}$`)},
	{"openai_org_key", regexp.MustCompile(`^org-[a-zA-Z0-9]{24}$`)},
	{"anthropic_api_key", regexp.MustCompile(`^sk-ant-api\d{2}-[a-zA-Z0-9\-_]{80,}$`)},
	{"vault_service_token", regexp.MustCompile(`^hvs\.[a-zA-Z0-9]{24,}$`)},
	{"vault_token", regexp.MustCompile(`^s\.[a-zA-Z0-9]{24}$`)},
	{"vault_batch_token", regexp.MustCompile(`^b\.[a-zA-Z0-9]{24}$`)},
	{"gitlab_pat", regexp.MustCompile(`^glpat-[a-zA-Z0-9]{20}$`)},
	{"gitlab_pipeline", regexp.MustCompile(`^glcbt-[a-zA-Z0-9]{20}$`)},
	{"gitlab_runner", regexp.MustCompile(`^glrt-[a-zA-Z0-9]{20}$`)},
	{"gitlab_deploy", regexp.MustCompile(`^gldt-[a-zA-Z0-9]{20}$`)},
	{"stripe_live_key", regexp.MustCompile(`^sk_live_[0-9a-zA-Z]{24,}$`)},
	{"stripe_test_key", regexp.MustCompile(`^sk_test_[0-9a-zA-Z]{24,}$`)},
	{"stripe_restricted_key", regexp.MustCompile(`^rk_(live|test)_[0-9a-zA-Z]{24,}$`)},
	{"stripe_publishable_key", regexp.MustCompile(`^pk_(live|test)_[0-9a-zA-Z]{24,}$`)},
	{"docker_token", regexp.MustCompile(`^dckr_pat_[a-zA-Z0-9_\-]{27,}$`)},
	{"npm_token", regexp.MustCompile(`^npm_[a-zA-Z0-9]{36}$`)},
	{"pypi_token", regexp.MustCompile(`^pypi-[a-zA-Z0-9_\-]{100,}$`)},
	{"slack_token", regexp.MustCompile(`^xox[baprs]-[0-9a-zA-Z\-]+$`)},
	{"slack_webhook", regexp.MustCompile(`^https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+$`)},
	{"discord_webhook", regexp.MustCompile(`^https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+$`)},
	{"twilio_api_key", regexp.MustCompile(`^SK[a-z0-9]{32}$`)},
	{"twilio_account_sid", regexp.MustCompile(`^AC[a-z0-9]{32}$`)},
	{"sendgrid_api_key", regexp.MustCompile(`^SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}$`)},
	{"api_key", regexp.MustCompile(`^key-[a-z0-9]{32}$`)}, // e.g., Mailgun
	{"digitalocean_token", regexp.MustCompile(`^dop_v1_[a-f0-9]{64}$`)},
	{"shopify_access_token", regexp.MustCompile(`^shpat_[a-f0-9]{32}$`)},
	{"shopify_custom_token", regexp.MustCompile(`^shpca_[a-f0-9]{32}$`)},
	{"shopify_private_token", regexp.MustCompile(`^shppa_[a-f0-9]{32}$`)},
	{"shopify_shared_secret", regexp.MustCompile(`^shpss_[a-f0-9]{32}$`)},
	{"square_secret", regexp.MustCompile(`^sq0csp-[0-9a-zA-Z_\-]{43}$`)},
	{"square_access", regexp.MustCompile(`^sq0atp-[0-9a-zA-Z_\-]{22}$`)},
	{"sentry_dsn", regexp.MustCompile(`^https://[a-f0-9]{32}@[a-z0-9.\-]+/[0-9]+$`)},
}

// pemPrivateKeyRe matches a PEM private-key armor header.
// Scanned against the raw body since PEM blocks may span template literals or byte arrays.
var pemPrivateKeyRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)

// extractSecrets returns credential matches from literals and PEM matches from src.
func extractSecrets(src []byte, literals []string) []protocol.ExtractedSecret {
	var out []protocol.ExtractedSecret
	for _, lit := range literals {
		for _, p := range literalSecretPatterns {
			if p.re.MatchString(lit) {
				out = append(out, protocol.ExtractedSecret{
					Kind:  p.kind,
					Value: lit,
				})
				break
			}
		}
	}
	if pemPrivateKeyRe.Match(src) {
		out = append(out, protocol.ExtractedSecret{
			Kind:  "private_key",
			Value: "-----BEGIN PRIVATE KEY-----",
		})
	}
	return out
}
