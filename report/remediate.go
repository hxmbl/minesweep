package report

import (
	"minesweep/findings"
)

var ruleRemediations = map[string]string{
	"aws-access-key-id":          "Rotate this key in the AWS IAM console, remove it from the file, and purge it from git history (e.g. git filter-repo). Consider switching to short-lived IAM roles.",
	"aws-secret-key":             "Rotate this secret key in the AWS IAM console, then remove it from the file and purge git history. Store it in a secrets manager instead.",
	"aws-session-token":          "This temporary token grants AWS access until it expires. Revoke the session it came from and remove it from the file.",
	"azure-client-secret":        "Rotate this secret in Azure Portal (App registrations), remove it from the file, and purge git history.",
	"azure-connection-string":    "Rotate the storage account key behind this connection string in the Azure Portal, then move the connection string to configuration or a secrets manager.",
	"azure-storage-account-key":  "Regenerate this storage account key in the Azure Portal (rotating may require updating services that use it).",
	"azure-sas-token":            "Revoke this shared access signature by rotating the signing key on the storage account.",
	"github-pat":                 "Revoke this token at github.com/settings/tokens and generate a new one. Purge git history so it cannot be replayed.",
	"github-app-token":           "Revoke this token from your GitHub App settings and generate a fresh installation token.",
	"github-oauth-token":         "Revoke this OAuth token in your GitHub application settings; anyone holding it can act as the authorized user.",
	"github-refresh-token":       "Revoke this refresh token in GitHub settings; it can be exchanged for new access tokens.",
	"gcp-service-account-key":    "Rotate this service account key in Google Cloud IAM, remove it from the file, and purge git history. Prefer workload identity over downloaded keys.",
	"gcp-oauth-token":            "Revoke this OAuth token via the Google account's third-party access page; it grants API access until revoked or expired.",
	"google-api-key":             "Restrict this API key to specific APIs and referrers in Google Cloud Console, rotate it, and move it out of source control.",
	"google-oauth-private-key":   "Rotate this service account private key in Google Cloud IAM and purge git history. Anyone with this key can authenticate as the service account.",
	"ssh-private-key":            "Treat this key as compromised: remove it from the repo, purge git history, and replace it with a new key pair. Private keys must never be committed, even encrypted ones.",
	"pgp-private-key":            "Treat this key as compromised: revoke it on a public keyserver if published, generate a replacement, and purge git history.",
	"generic-rsa-private-key":    "Generate a new RSA key pair, securely delete the exposed one everywhere (including git history), and update anything that trusted it.",
	"generic-pkcs8-key":          "Generate a new key pair, securely delete the exposed PKCS#8 key everywhere (including git history), and re-deploy the replacement.",
	"generic-pem-certificate":    "Check whether this PEM block contains a private key rather than just a certificate; if so, rotate the key pair.",
	"jwt-encoded":                "Treat this JWT as compromised until it expires. Shorten its remaining lifetime where possible and investigate how it leaked.",
	"jwt-bearer":                 "Treat this bearer token as compromised until it expires. Rotate the credentials behind it if the token is long-lived.",
	"jwt-standalone":             "Verify whether this is a real token or sample data. Real tokens grant access until expiry - shorten lifetime and re-issue.",
	"jose-token":                 "Treat this JOSE token as compromised until expiry; rotate the signing credentials if it is long-lived.",
	"database-url":               "Rotate the password embedded in this database URL and move the full URL to an environment variable or secrets manager.",
	"postgres-connection-string": "Change this PostgreSQL user's password and move the connection string to environment configuration.",
	"mysql-connection-string":    "Change this MySQL user's password and move the connection string to environment configuration.",
	"mongodb-connection-string":  "Change this MongoDB user's password and move the connection string to environment configuration.",
	"redis-connection-string":    "Set a password on this Redis instance (requirepass/ACL) and keep the URL out of source control.",
	"database-password":          "Rotate this database password and load it from an environment variable or secrets manager instead of hardcoding it.",
	"generic-npm-token":          "Revoke this token at npmjs.com -> Access Tokens and publish any packages it could have touched under a new token.",
	"generic-slack-token":        "Revoke this token in your Slack app settings (api.slack.com) and issue a new one.",
	"generic-slack-webhook":      "Rotate this incoming webhook URL in your Slack app configuration; anyone with the URL can post to the channel.",
	"stripe-secret-key":          "Roll this Stripe secret key in the Stripe dashboard (Developers -> API keys) and update your deployment secrets.",
	"stripe-restricted-key":      "Revoke this restricted key in the Stripe dashboard and create a replacement with only the permissions needed.",
	"stripe-webhook-secret":      "Re-roll this webhook signing secret in the Stripe dashboard and update the endpoint that verifies signatures.",
	"sendgrid-api-key":           "Delete this API key in the SendGrid console and create a scoped replacement; leaked keys are commonly abused for spam.",
	"mailgun-api-key":            "Rotate this Mailgun API key in the Mailgun dashboard and update your deployment secrets.",
	"twilio-api-key":             "Rotate this Twilio credential in the Twilio console; leaked keys can incur large usage charges.",
	"twilio-account-sid":         "Account SIDs are identifiers, not secrets, but confirm no matching auth token was committed alongside it.",
	"generic-twilio-key":         "Rotate this Twilio credential in the Twilio console; leaked keys can incur large usage charges.",
	"generic-heroku-api":         "Rotate this Heroku API key (heroku authorizations:create) and update deployment integrations.",
	"generic-docker-config":      "config.json can contain registry auth blobs. Run 'docker logout' on the machine that produced it and never commit the file.",
	"entropy-high":               "This string looks randomly generated, which often means a secret. Verify what it is before sharing the file.",
	"base64-high-entropy":        "This looks like base64-encoded high-entropy data, often an encoded secret or key. Decode and verify it.",
	"symlink-detected":           "Symlinks can point outside the scanned directory. Confirm it targets something intentional.",
	"binary-file-detected":       "Binary files were skipped during scanning; secrets inside them (e.g. baked-in config) would not be detected.",
	"executable-file-detected":   "Executable files were skipped during scanning; consider auditing them separately.",
}

type tagRemediation struct {
	tag  string
	text string
}

var tagRemediations = []tagRemediation{
	{"private-key", "Private keys must never be committed or shared. Replace this key pair and purge the old key from git history."},
	{"jwt", "Tokens like this grant access until they expire. Treat it as compromised, shorten its lifetime, and keep future tokens out of source control."},
	{"credentials", "Rotate this credential with its provider, remove it from the file, and load it from an environment variable or secrets manager instead."},
	{"api-key", "Rotate this API key with its provider and load it from an environment variable or secrets manager instead of hardcoding it."},
	{"token", "Rotate or revoke this token with its provider; treat it as readable by anyone who has seen this file."},
	{"oauth", "Revoke this OAuth credential with the provider and re-authorize with a fresh grant."},
	{"password", "Change this password and load it from an environment variable or secrets manager instead of hardcoding it."},
	{"database", "Rotate these database credentials and keep connection strings in environment configuration."},
	{"certificate", "Confirm this certificate does not embed a private key; certificates themselves are usually safe to commit."},
	{"docker", "Registry credentials often hide in Docker config files. Log out and back in, and exclude config.json from version control."},
	{"registry", "Rotate this registry token and configure your client to read it from the environment."},
	{"email", "Rotate this email-provider credential; leaked mail keys are quickly abused for phishing and spam."},
	{"communication", "Rotate this messaging credential with its provider; leaked keys can incur large usage charges."},
	{"payments", "Rotate this payments credential in the provider dashboard and update your deployment secrets."},
	{"env", "Environment-style assignments often hold real values in practice. Move the actual value into a local .env file that is gitignored."},
	{"cloud", "Rotate this cloud credential in the provider console and prefer short-lived, role-based access over static keys."},
	{"vcs", "Rotate this repository token with your VCS provider and store it in a credential helper."},
	{"auth", "Rotate this authentication material and keep future values out of source control."},
}

func RemediationText(ruleID string, tags []string) string {
	if txt, ok := ruleRemediations[ruleID]; ok {
		return txt
	}
	for _, tr := range tagRemediations {
		for _, t := range tags {
			if t == tr.tag {
				return tr.text
			}
		}
	}
	return ""
}

func remediationFor(f findings.Finding) string {
	if txt := RemediationText(f.RuleID, f.Tags); txt != "" {
		return txt
	}
	switch {
	case f.Severity >= findings.SeverityCritical:
		return "Treat this value as compromised: rotate it with the responsible provider and remove it from the file."
	case f.Severity >= findings.SeverityHigh:
		return "Verify whether this is a real secret; if so, rotate it and keep future values out of source control."
	default:
		return ""
	}
}
