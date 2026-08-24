package detectors

import (
	"bytes"
	"regexp/syntax"
	"strings"
)

// gateAlt is an OR-group: a match may contain any one of the alternatives.
// The byte forms are precompiled once at extraction so the hot path never
// allocates per file.
type gateAlt struct {
	alts     []string
	altBytes [][]byte
	fold     bool
}

// gateBranch is an AND-group: every conjunct must be satisfiable.
type gateBranch []gateAlt

// literalGate is a DNF condition that is necessary for a pattern to match:
// OR of branches, each branch an AND of OR-groups. If the condition fails,
// the regex cannot match the input and the scan can be skipped entirely.
// Extraction is deliberately conservative: only literals in required
// positions are collected, so a passing gate never implies a match and a
// failing gate always implies a non-match.
type literalGate []gateBranch

func (g literalGate) satisfied(content, lowered []byte) bool {
	for _, branch := range g {
		ok := true
		for _, conj := range branch {
			hay := content
			if conj.fold {
				hay = lowered
			}
			if hay == nil || !containsAny(hay, conj.altBytes) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func containsAny(hay []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(hay, n) {
			return true
		}
	}
	return false
}

const maxGateBranches = 64

// extractLiteralGate parses a regex and returns the necessary-literal
// condition, or nil when no sound gate can be derived (or the expression is
// too branched to be worth it).
func extractLiteralGate(pattern string) literalGate {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	branches := collectRequired(re)
	if len(branches) == 0 || len(branches) > maxGateBranches {
		return nil
	}
	for bi := range branches {
		for ci := range branches[bi] {
			alt := &branches[bi][ci]
			alt.altBytes = make([][]byte, 0, len(alt.alts))
			for _, a := range alt.alts {
				if a != "" {
					alt.altBytes = append(alt.altBytes, []byte(a))
				}
			}
			if len(alt.altBytes) == 0 {
				return nil
			}
		}
	}
	return branches
}

// collectRequired returns the OR-branches contributed by re. A nil result
// means "no requirement".
func collectRequired(re *syntax.Regexp) []gateBranch {
	switch re.Op {
	case syntax.OpLiteral:
		lit := string(re.Rune)
		if lit == "" {
			return nil
		}
		if re.Flags&syntax.FoldCase != 0 {
			// The syntax parser folds case-insensitive literals to a fixed
			// case; normalize to lowercase so the gate can search a lowered
			// haystack.
			return []gateBranch{{gateAlt{alts: []string{strings.ToLower(lit)}, fold: true}}}
		}
		return []gateBranch{{gateAlt{alts: []string{lit}, fold: false}}}

	case syntax.OpCapture:
		return collectRequired(re.Sub[0])

	case syntax.OpConcat:
		var acc []gateBranch
		for _, sub := range mergeAdjacentLiterals(re.Sub) {
			part := collectRequired(sub)
			switch {
			case len(part) == 0:
				continue
			case len(acc) == 0:
				acc = part
			default:
				merged := crossJoin(acc, part)
				if merged == nil {
					return nil
				}
				acc = merged
			}
			if len(acc) > maxGateBranches {
				return nil
			}
		}
		return acc

	case syntax.OpAlternate:
		// An alternation only imposes a literal requirement if EVERY
		// branch does; a single requirement-free branch (a character
		// class, anchor, or wildcard) lets the whole group match without
		// any literal, so the correct answer is "no requirement".
		var acc []gateBranch
		for _, sub := range re.Sub {
			part := collectRequired(sub)
			if len(part) == 0 {
				return nil
			}
			acc = append(acc, part...)
			if len(acc) > maxGateBranches {
				return nil
			}
		}
		return acc

	case syntax.OpPlus:
		return collectRequired(re.Sub[0])

	case syntax.OpRepeat:
		if re.Min >= 1 {
			return collectRequired(re.Sub[0])
		}
		return nil

	default:
		// Optional quantifiers, character classes, wildcards, anchors,
		// and empty-width assertions impose no literal requirement.
		return nil
	}
}

// crossJoin AND-combines two branch sets. Returns nil when the product would
// blow past the branch cap.
func crossJoin(a, b []gateBranch) []gateBranch {
	if len(a)*len(b) > maxGateBranches {
		return nil
	}
	out := make([]gateBranch, 0, len(a)*len(b))
	for _, ab := range a {
		for _, bb := range b {
			merged := make(gateBranch, 0, len(ab)+len(bb))
			merged = append(merged, ab...)
			merged = append(merged, bb...)
			out = append(out, merged)
		}
	}
	return out
}

// mergeAdjacentLiterals joins neighboring literal nodes with identical case
// semantics back into single words. Case-folding splits "postgres" into
// per-rune literals during parsing; without this the gate degrades to
// single-letter requirements.
func mergeAdjacentLiterals(subs []*syntax.Regexp) []*syntax.Regexp {
	out := make([]*syntax.Regexp, 0, len(subs))
	for _, sub := range subs {
		if sub.Op == syntax.OpLiteral && len(out) > 0 {
			last := out[len(out)-1]
			if last.Op == syntax.OpLiteral &&
				(last.Flags&syntax.FoldCase != 0) == (sub.Flags&syntax.FoldCase != 0) {
				last.Rune = append(last.Rune, sub.Rune...)
				continue
			}
		}
		out = append(out, sub)
	}
	return out
}
