package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"minesweep/filesystem"
	"minesweep/findings"
)

// regexDetector builds a detector over the shipped rules, which is what the CLI
// uses when --rules is not given.
func regexDetector(t *testing.T) *RegexDetector {
	t.Helper()
	d, err := NewRegexDetector("")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func scanText(t *testing.T, name, body string) []findings.Finding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := filesystem.NewFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.LoadContent(); err != nil {
		t.Fatal(err)
	}
	f.SetFindingBudget(1000)
	return regexDetector(t).Detect(f)
}

// A checked-in .env.example is the single most common source of false positives
// in this tool's world. This exact body produced fourteen findings:
//
//	DB_PASSWORD=xxxxxxxx   -> database credentials + generic password + env-password
//	API_KEY=changeme       -> API Key Variable (MEDIUM)
//	SECRET=placeholder     -> Password Variable (HIGH, redact)
//	CLIENT_SECRET=REPLACE_ME
//
// Each finding was individually defensible. Together they are a reason to
// delete the pre-commit hook, which is the bypass the security rules exist to
// make unnecessary.
//

// The reviewer's first finding, verbatim. A 52-character Python function name is
// 70%-confidence "high entropy" because the line contains the substring `key`
// inside `monkeypatch`. It is a definition: a definition cannot be a credential,
// and no entropy threshold can tell the two apart.
func TestLongFunctionNameIsNotASecret(t *testing.T) {
	body := "def test_backend_asks_about_the_library_without_importing_it(monkeypatch):\n    assert True\n"

	d := NewEntropyDetector()
	dir := t.TempDir()
	p := filepath.Join(dir, "test_thing.py")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := filesystem.NewFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.LoadContent(); err != nil {
		t.Fatal(err)
	}
	f.SetFindingBudget(1000)
	if got := d.Detect(f); len(got) != 0 {
		t.Errorf("entropy reported a function definition: %+v", got)
	}
}

// The narrowness check for the fix above: the same shape with a real secret on
// the line must still be reported. If identifier position were suppressed too
// broadly, this would go quiet too.
func TestRealSecretOnALineWithADefinitionIsStillFound(t *testing.T) {
	body := "def configure_client(monkeypatch):\n" +
		"    client.set_api_key(\"\x41KIAZQ4TLN2XRH7JWBVG\")\n" +
		"    client.connect(PRIVATE_KEY_PATH)\n"

	got := scanText(t, "client.py", body)
	if len(got) == 0 {
		t.Error("a real key next to a function definition must still be reported")
	}
}

// STRM-723: an arbitrary UUID is not an Azure tenant ID. Only a tenant/directory
// key gives the UUID a credential role.
func TestArbitraryUUIDIsNotAzureTenantID(t *testing.T) {
	body := "request_id = \"3f6b8a2e-9c4d-4e1a-b7c8-2d5a6f1e3c4d\"\n" +
		"trace = 9b2f4c8e-1a3d-4f5b-8c6d-7e8a9b0c1d2e\n"

	for _, f := range scanText(t, "app.py", body) {
		if f.RuleID == "azure-tenant-id" {
			t.Fatalf("arbitrary UUID flagged as azure-tenant-id: %+v", f)
		}
	}
}

func TestTenantKeyedUUIDIsAzureTenantID(t *testing.T) {
	body := "tenant_id = \"3f6b8a2e-9c4d-4e1a-b7c8-2d5a6f1e3c4d\"\n"

	found := false
	for _, f := range scanText(t, "app.py", body) {
		if f.RuleID == "azure-tenant-id" {
			found = true
		}
	}
	if !found {
		t.Fatal("tenant_id-keyed UUID must still be flagged as azure-tenant-id")
	}
}

// STRM-723: an ordinary `project` assignment is not a GCP project ID.
func TestOrdinaryProjectAssignmentIsNotGCPProjectID(t *testing.T) {
	body := "project = \"ItsDangerous\"\n" // pallets/itsdangerous docs/conf.py

	for _, f := range scanText(t, "conf.py", body) {
		if f.RuleID == "gcp-project-id" {
			t.Fatalf("ordinary project assignment flagged as gcp-project-id: %+v", f)
		}
	}
}

func TestGCPProjectAssignmentIsGCPProjectID(t *testing.T) {
	body := "project = \"my-gcp-project-1\"\n"

	found := false
	for _, f := range scanText(t, "app.py", body) {
		if f.RuleID == "gcp-project-id" {
			found = true
		}
	}
	if !found {
		t.Fatal("project-keyed lowercase value must still be flagged as gcp-project-id")
	}
}

// STRM-668/STRM-723: ordinary Rust identifiers/fields containing "project" are
// not GCP project IDs — the keyword must be bounded and the value lowercase.
func TestOrdinaryRustProjectIdentifiersAreNotGCPProjectID(t *testing.T) {
	body := "let by_project = some_value;\n" +
		"let channel_project = other_value;\n" +
		"pub struct Foo { pub project: Project }\n" +
		"let project_id = ProjectId::new();\n"

	for _, f := range scanText(t, "lib.rs", body) {
		if f.RuleID == "gcp-project-id" {
			t.Fatalf("ordinary Rust identifier flagged as gcp-project-id: %+v", f)
		}
	}
}
