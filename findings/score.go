package findings

import (
	"fmt"
	"math"
	"path"
	"strings"
)

// The risk score answers one question: how likely is it that *this* tree holds
// a live secret, and how much would one cost?
//
// It used to answer a much smaller question. computeRiskScore took the single
// highest severity present and mapped it to one of five fixed values, so one
// hardcoded password and four hundred of them scored identically, a 35%-confident
// guess weighed as much as a 95%-confident key, a fixture scored like a
// production config, and a live AWS key was capped below "critical" unless an
// unrelated private key happened to sit beside it. The number moved; it did not
// mean anything.
//
// This model keeps the 0-100 scale and the band labels, and makes the number a
// function of the evidence:
//
//  1. Each finding contributes an *impact*: a severity floor, scaled by how
//     confident the detector is that the match is real, by how exposed the file
//     is, and by whether the credential class is one that cannot simply be
//     rotated.
//  2. The worst finding sets the floor — a tree is never "safe" because its
//     other findings are quiet — and the remaining findings add a bounded,
//     confidence-weighted volume term with diminishing returns, so a long tail
//     of weak matches can raise the score but cannot saturate it to 100 on its
//     own.
//
// The result is deliberately monotonic in every axis: more findings, higher
// confidence, a more exposed path, or a worse severity can only raise the score
// or leave it unchanged. A score that can fall when you add a finding is a score
// nobody will trust.

// Impact anchors: the score a finding of each severity would carry at full
// confidence in a neutral, unremarkable file. They are chosen so that a single
// high-confidence finding lands in the middle of its own band rather than
// straddling two.
const (
	impactInfo     = 9.0
	impactLow      = 28.0
	impactMedium   = 56.0
	impactHigh     = 76.0
	impactCritical = 92.0
)

// Volume term. The weighted count below is measured in "one confident finding",
// so a critical credential contributes ~0.9 and a low-confidence guess ~0.3.
const (
	volumeK   = 13.0
	volumeCap = 18.0
)

// Exposure multipliers. These shift the likelihood that a match is a live
// credential, not whether it should be reported: a test fixture and a README
// fence are still listed and still gate CI, they just carry less weight than a
// key sitting in `.env` at the repository root.
const (
	exposureBase      = 1.0
	exposureTest      = 0.70
	exposureDoc       = 0.85
	exposureSensitive = 1.15
)

// Category multipliers for credential classes where severity alone undersells
// the consequence. A private key cannot be rotated by reissuing a token, and
// cloud and payment credentials typically fan out into further access.
const (
	categoryBase       = 1.0
	categoryPrivateKey = 1.15
	categoryHighBlast  = 1.05
)

// Confidence is a multiplier in [confidenceFloor, 1]: a 0.95 match counts for
// full weight, a 0.00 match still counts for close to half.
const (
	confidenceFloor = 0.45
	confidenceSpan  = 0.55
)

// impactCeiling is the top of the 0-100 scale.
const impactCeiling = 100.0

// severityImpact is the pre-confidence impact anchor for a severity.
func severityImpact(s Severity) float64 {
	switch {
	case s >= SeverityCritical:
		return impactCritical
	case s >= SeverityHigh:
		return impactHigh
	case s >= SeverityMedium:
		return impactMedium
	case s >= SeverityLow:
		return impactLow
	default:
		return impactInfo
	}
}

// confidenceFactor maps detector confidence in [0,1] to a multiplier in
// [confidenceFloor, 1]. Confidence is evidence, not a veto: a low-confidence
// match on a critical rule is still worth investigating, so the floor stays well
// above zero. The floor is what keeps a bare "0.35 generic key" from collapsing
// to nothing while still ranking it far below a 0.95 live key.
func confidenceFactor(conf float64) float64 {
	switch {
	case conf < 0:
		conf = 0
	case conf > 1:
		conf = 1
	}
	return confidenceFloor + confidenceSpan*conf
}

// categoryFactor rewards credential classes whose damage outlasts a rotation.
func categoryFactor(tags []string) float64 {
	f := categoryBase
	for _, t := range tags {
		switch t {
		case "private-key":
			return categoryPrivateKey
		case "cloud", "payments":
			if f < categoryHighBlast {
				f = categoryHighBlast
			}
		}
	}
	return f
}

// exposureFactor scores how likely a path is to be a real deployment artifact.
//
// Path only ever multiplies an existing finding, so a wrong guess here nudges
// the number rather than inventing or hiding a result.
func exposureFactor(file string) float64 {
	p := strings.ToLower(strings.ReplaceAll(normalizeBaselineFile(file), "\\", "/"))
	if p == "" {
		return exposureBase
	}
	base := path.Base(p)
	ext := path.Ext(base)

	if isTestLikePath(p, base, ext) {
		return exposureTest
	}
	if isDocLikePath(p, ext) {
		return exposureDoc
	}
	if isSensitiveName(base, ext) {
		return exposureSensitive
	}
	return exposureBase
}

// isTestLikePath recognises the same conventions the walker uses to skip test
// files, plus the directories fixtures and examples usually live in. It is
// intentionally a little broader than the skip rule: a finding that survived
// into the report should still be discounted for living in `testdata/`.
func isTestLikePath(p, base, ext string) bool {
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "test", "tests", "testdata", "__tests__", "spec", "specs",
			"fixture", "fixtures", "test-fixtures", "mocks", "__mocks__":
			return true
		}
	}
	name := strings.TrimSuffix(base, ext)
	if strings.HasSuffix(name, "_test") || strings.HasSuffix(name, "_spec") {
		return true
	}
	if strings.HasPrefix(name, "test_") || strings.HasPrefix(name, "spec_") {
		return true
	}
	if strings.HasSuffix(base, ".test") || strings.HasSuffix(base, ".spec") {
		return true
	}
	return false
}

func isDocLikePath(p, ext string) bool {
	switch ext {
	case ".md", ".markdown", ".mdx", ".rst", ".adoc", ".asciidoc":
		return true
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "docs", "doc", "examples", "example", "samples", "sample":
			return true
		}
	}
	return false
}

// isSensitiveName names the files where a hit is most likely to be a real,
// deployed credential rather than a sample: dotenv files, key material, state
// files and netrc-style credential stores.
func isSensitiveName(base, ext string) bool {
	switch base {
	case ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
		"credentials", "credentials.json", ".npmrc", ".netrc", ".dockercfg", ".pypirc":
		return true
	}
	if strings.HasPrefix(base, ".env") {
		return true
	}
	switch ext {
	case ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".tfstate", ".ppk":
		return true
	}
	return false
}

// findingImpact is the per-finding 0-100 contribution before aggregation.
func findingImpact(f Finding, exposure float64) float64 {
	impact := severityImpact(f.Severity) *
		confidenceFactor(f.Confidence) *
		exposure *
		categoryFactor(f.Tags)
	if impact > impactCeiling {
		return impactCeiling
	}
	if impact < 0 {
		return 0
	}
	return impact
}

// computeRiskScore returns the 0-100 risk score and a short, human-readable
// explanation of how it was reached. The explanation is part of the return
// value on purpose: a score a reader cannot audit is a number they will learn to
// ignore.
func computeRiskScore(fs []Finding) (RiskScore, []string) {
	if len(fs) == 0 {
		return RiskScoreNone, nil
	}

	var (
		maxImpact  float64
		worst      Finding
		worstSet   bool
		weighted   float64
		discounted int
		qualifying int
	)

	for _, f := range fs {
		// Informational findings (a detected binary, a symlink, an executable)
		// are coverage notes, not secrets. A tree that contains only those has
		// no *detected* risk and must still score 0, or a scan of compiled
		// artefacts would read as riskier than a scan of source.
		if f.Severity < SeverityLow {
			continue
		}

		exposure := exposureFactor(f.File)
		impact := findingImpact(f, exposure)

		if impact > maxImpact {
			maxImpact, worst, worstSet = impact, f, true
		}
		weighted += impact / 100
		qualifying++
		if exposure < exposureBase {
			discounted++
		}
	}

	// The worst finding sets the floor rather than being counted twice in the
	// volume term.
	if worstSet {
		weighted -= maxImpact / 100
	}
	if weighted < 0 {
		weighted = 0
	}

	volume := volumeK * math.Log2(1+weighted)
	if volume > volumeCap {
		volume = volumeCap
	}

	raw := maxImpact + volume
	if raw > impactCeiling {
		raw = impactCeiling
	}
	if raw < 0 {
		raw = 0
	}
	score := RiskScore(int(math.Round(raw)))

	return score, scoreDrivers(maxImpact, volume, worst, worstSet, qualifying, discounted, raw >= impactCeiling)
}

func scoreDrivers(maxImpact, volume float64, worst Finding, worstSet bool, qualifying, discounted int, capped bool) []string {
	var out []string

	if worstSet {
		out = append(out, fmt.Sprintf(
			"highest-impact finding: %s (%s, %.0f%% confidence) — %d/100",
			worst.Type, worst.Severity, worst.Confidence*ConfidenceScale, int(math.Round(maxImpact))))
	}
	if volume >= 0.5 {
		out = append(out, fmt.Sprintf(
			"%d additional finding(s) add %d/100 by confidence-weighted volume",
			qualifying-1, int(math.Round(volume))))
	}
	if discounted > 0 {
		out = append(out, fmt.Sprintf(
			"%d finding(s) in test or documentation files were discounted", discounted))
	}
	if capped {
		out = append(out, "score is capped at 100/100")
	}

	return out
}
