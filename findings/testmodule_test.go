package findings

import "testing"

func TestFilterRustTestModuleFindings(t *testing.T) {
	lines := []string{
		"fn prod() { let k = \"secret\"; }", // 1
		"",                                  // 2
		"#[cfg(test)]",                      // 3
		"mod tests {",                       // 4
		"    #[test]",                       // 5
		"    fn it_works() { let k = \"secret\"; }", // 6
		"}", // 7
	}
	fs := []Finding{
		{File: "lib.rs", Line: 1, RuleID: "r"},
		{File: "lib.rs", Line: 6, RuleID: "r"},
	}
	got := FilterRustTestModuleFindings(fs, fakeLines(lines))
	if len(got) != 1 || got[0].Line != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestFilterRustTestModuleFindings_NotCfgTest(t *testing.T) {
	lines := []string{
		"#[cfg(not(test))]",
		"mod prod {",
		"  fn f() { let k = \"secret\"; }",
		"}",
	}
	fs := []Finding{{File: "lib.rs", Line: 3, RuleID: "r"}}
	got := FilterRustTestModuleFindings(fs, fakeLines(lines))
	if len(got) != 1 {
		t.Fatalf("not(test) module should not be filtered: %+v", got)
	}
}

func TestFilterRustTestModuleFindings_ExternalModule(t *testing.T) {
	lines := []string{
		"#[cfg(test)]",
		"mod tests;",
		"fn prod() { let k = \"secret\"; }",
	}
	fs := []Finding{{File: "lib.rs", Line: 3, RuleID: "r"}}
	got := FilterRustTestModuleFindings(fs, fakeLines(lines))
	if len(got) != 1 {
		t.Fatalf("external mod should not filter later prod lines: %+v", got)
	}
}
