package filesystem

import "testing"

// C5: ClaimFinding derived "unlimited" from FindingBudget <= 0, which the
// decrement also reached. A budget of 3 answered true forever and never set
// FindingBudgetHit, so the per-file budget was dead code and one file could
// materialise every finding it could produce.
func TestClaimFindingDeniesWhenBudgetExhausted(t *testing.T) {
	f := &File{}
	f.SetFindingBudget(3)

	var got []bool
	for i := 0; i < 8; i++ {
		got = append(got, f.ClaimFinding())
	}
	want := []bool{true, true, true, false, false, false, false, false}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("budget=3 claim %d = %v, want %v (all: %v)", i+1, got[i], want[i], got)
		}
	}
	if !f.FindingBudgetHit {
		t.Error("FindingBudgetHit must be set once the budget is spent")
	}
	if f.RemainingFindingBudget() != 0 {
		t.Errorf("remaining budget = %d, want 0", f.RemainingFindingBudget())
	}
}

func TestClaimFindingZeroBudgetDeniesImmediately(t *testing.T) {
	f := &File{}
	f.SetFindingBudget(0)
	if f.ClaimFinding() {
		t.Fatal("an armed budget of zero must deny")
	}
	if !f.FindingBudgetHit {
		t.Error("FindingBudgetHit must be set")
	}
}

// A zero-valued File must stay usable: detectors and library callers build
// these by hand, and an unarmed budget must mean "no limit".
func TestZeroValueFileIsUnlimited(t *testing.T) {
	f := &File{}
	for i := 0; i < 1000; i++ {
		if !f.ClaimFinding() {
			t.Fatalf("unarmed File denied at claim %d", i+1)
		}
	}
	if f.FindingBudgetHit {
		t.Error("unarmed File must never report the budget as hit")
	}
}

func TestSetFindingBudgetDisarmsOnNegative(t *testing.T) {
	for _, n := range []int{FindingBudgetUnlimited, -5} {
		f := &File{}
		f.SetFindingBudget(1)
		f.SetFindingBudget(n)
		if !f.ClaimFinding() {
			t.Errorf("SetFindingBudget(%d) did not disarm the budget", n)
		}
	}
}

// A synthetic file standing in for another must inherit whatever budget that
// file has left, including "none".
func TestInheritFindingBudget(t *testing.T) {
	src := &File{}
	src.SetFindingBudget(0) // spent

	dst := &File{}
	dst.InheritFindingBudget(src)
	if dst.ClaimFinding() {
		t.Error("inherited exhausted budget did not deny")
	}

	free := &File{}
	dst2 := &File{}
	dst2.InheritFindingBudget(free)
	for i := 0; i < 10; i++ {
		if !dst2.ClaimFinding() {
			t.Fatalf("inherited unarmed budget denied at claim %d", i+1)
		}
	}
}

func TestRemainingFindingBudgetTracksClaims(t *testing.T) {
	f := &File{}
	f.SetFindingBudget(10)
	if got := f.RemainingFindingBudget(); got != 10 {
		t.Fatalf("remaining = %d, want 10", got)
	}
	for i := 0; i < 4; i++ {
		f.ClaimFinding()
	}
	if got := f.RemainingFindingBudget(); got != 6 {
		t.Fatalf("remaining = %d, want 6", got)
	}
}
