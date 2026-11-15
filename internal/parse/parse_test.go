package parse

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestJSONAndHeredoc(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "role.json")
	body := []byte(`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:example-org/example-repo:ref:refs/heads/main"}}}}`)
	if err := os.WriteFile(jsonPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Statements) != 1 {
		t.Fatalf("statements: %#v", got)
	}
	if got[0].Statements[0].Principals[0].Kind != "Federated" {
		t.Fatalf("principal: %#v", got[0].Statements[0].Principals)
	}

	tf := filepath.Join(dir, "role.tf")
	tfBody := "resource \"aws_iam_role\" \"gha\" {\n  assume_role_policy = <<POLICY\n" + string(body) + "\nPOLICY\n}\n"
	if err := os.WriteFile(tf, []byte(tfBody), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = ReadFile(tf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Statements[0].Actions[0] != "sts:AssumeRoleWithWebIdentity" {
		t.Fatalf("heredoc: %#v", got)
	}
}

func TestRejectsSymlinkAndBrokenJSON(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte(`{"Statement":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link); err == nil {
		t.Fatal("symlink was accepted")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"Statement"`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(bad); err == nil {
		t.Fatal("broken JSON was accepted")
	}
}

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const wildcardDoc = `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}}`

func TestTerraformUnreadableFormsAreUnparsed(t *testing.T) {
	cases := map[string]string{
		"jsonencode": "resource \"aws_iam_role\" \"a\" {\n  assume_role_policy = jsonencode({Principal = \"*\"})\n}\n",
		"data":       "resource \"aws_iam_role\" \"a\" {\n  assume_role_policy = data.aws_iam_policy_document.x.json\n}\n",
		"quoted":     "resource \"aws_iam_role\" \"a\" {\n  assume_role_policy = \"{}\"\n}\n",
		"no end":     "resource \"aws_iam_role\" \"a\" {\n  assume_role_policy = <<POLICY\n" + wildcardDoc + "\n}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ReadFile(writeTemp(t, "r.tf", body))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || len(got[0].Unparsed) != 1 || len(got[0].Statements) != 0 {
				t.Fatalf("want one policy with one Unparsed, got %#v", got)
			}
			if got[0].Unparsed[0].Line != 2 || got[0].Unparsed[0].Reason == "" {
				t.Fatalf("unparsed: %#v", got[0].Unparsed)
			}
		})
	}
}

func TestIndentedHeredoc(t *testing.T) {
	body := "resource \"aws_iam_role\" \"a\" {\n  assume_role_policy = <<-EOT\n    " + wildcardDoc + "\n    EOT\n}\n"
	got, err := ReadFile(writeTemp(t, "r.tf", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Unparsed) != 0 || len(got[0].Statements) != 1 {
		t.Fatalf("got %#v", got)
	}
}

func TestMultipleRolesEachGetAPolicyWithLabel(t *testing.T) {
	body := "resource \"aws_iam_role\" \"first\" {\n  assume_role_policy = <<POLICY\n" + wildcardDoc + "\nPOLICY\n}\n" +
		"resource \"aws_iam_role\" \"second\" {\n  assume_role_policy = <<-POLICY\n  " + wildcardDoc + "\n  POLICY\n}\n"
	got, err := ReadFile(writeTemp(t, "r.tf", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 policies, got %#v", got)
	}
	if !strings.Contains(got[0].Label, "first") || !strings.Contains(got[1].Label, "second") {
		t.Fatalf("labels: %q %q", got[0].Label, got[1].Label)
	}
	for _, p := range got {
		if len(p.Statements) != 1 || p.Statements[0].Principals[0].Kind != "Any" {
			t.Fatalf("policy %#v", p)
		}
	}
}

func TestLaterHeredocIsNotBorrowedByEarlierJsonencode(t *testing.T) {
	body := "resource \"aws_iam_role\" \"a\" {\n  assume_role_policy = jsonencode({Principal = \"*\"})\n}\n" +
		"resource \"aws_instance\" \"b\" {\n  user_data = <<EOT\n" + wildcardDoc + "\nEOT\n}\n"
	got, err := ReadFile(writeTemp(t, "r.tf", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Unparsed) != 1 || len(got[0].Statements) != 0 {
		t.Fatalf("got %#v", got)
	}
}

func TestBadJSONInHeredocIsAnError(t *testing.T) {
	body := "resource \"aws_iam_role\" \"a\" {\n  assume_role_policy = <<POLICY\n{oops\nPOLICY\n}\n"
	if _, err := ReadFile(writeTemp(t, "r.tf", body)); err == nil {
		t.Fatal("invalid JSON in a heredoc was accepted")
	}
}

func TestNumericPrincipals(t *testing.T) {
	for _, principal := range []string{`{"AWS":111122223333}`, `{"AWS":[111122223333]}`} {
		p, err := ParseJSON("x.json", []byte(`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":`+principal+`}}`))
		if err != nil {
			t.Fatal(err)
		}
		got := p.Statements[0].Principals
		if len(got) != 1 || got[0].Kind != "AWS" || got[0].Value != "111122223333" {
			t.Fatalf("%s: %#v", principal, got)
		}
	}
}

func TestUndecodablePrincipalIsAnError(t *testing.T) {
	for _, principal := range []string{`{"AWS":{"a":1}}`, `5`, `{"AWS":true}`, `{"AWS":[["x"]]}`} {
		_, err := ParseJSON("x.json", []byte(`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":`+principal+`}}`))
		if err == nil {
			t.Fatalf("principal %s was accepted", principal)
		}
	}
}

func TestNotPrincipalAndNotAction(t *testing.T) {
	p, err := ParseJSON("x.json", []byte(`{"Statement":{"Effect":"Allow","NotAction":["s3:*","sts:Get*"],"NotPrincipal":{"AWS":"arn:aws:iam::111122223333:root"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := p.Statements[0]
	if len(s.NotActions) != 2 || len(s.NotPrincipals) != 1 || s.NotPrincipals[0].Value != "arn:aws:iam::111122223333:root" {
		t.Fatalf("statement: %#v", s)
	}
}

func readErr(t *testing.T, path string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("ReadFile(%s) did not return within 5s", path)
		return nil
	}
}

func TestSpecialFilesAreRejectedWithoutHanging(t *testing.T) {
	if err := readErr(t, "/dev/zero"); err == nil {
		t.Fatal("/dev/zero was accepted")
	}
	fifo := filepath.Join(t.TempDir(), "pipe.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := readErr(t, fifo); err == nil {
		t.Fatal("FIFO was accepted")
	}
}

func TestSizeBound(t *testing.T) {
	doc := `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::111122223333:root"}}}`
	exact := doc + strings.Repeat(" ", MaxBytes-len(doc))
	if _, err := ReadFile(writeTemp(t, "exact.json", exact)); err != nil {
		t.Fatalf("exactly MaxBytes was rejected: %v", err)
	}
	if err := readErr(t, writeTemp(t, "big.json", exact+" ")); err == nil {
		t.Fatal("MaxBytes+1 was accepted")
	}
}

func TestSymlinkLastComponentIsRejected(t *testing.T) {
	dir := t.TempDir()
	target := writeTemp(t, "real.json", wildcardDoc)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := readErr(t, link); err == nil {
		t.Fatal("symlink was accepted")
	}
}

func TestEmptyOrMissingStatementIsAnError(t *testing.T) {
	for _, doc := range []string{`{"Statement":[]}`, `{"Statement":null}`, `{"Statement":{}}`, `{}`, `{"Version":"2012-10-17"}`} {
		if _, err := ParseJSON("x.json", []byte(doc)); err == nil {
			t.Fatalf("%s was accepted", doc)
		}
	}
}

func TestPrincipalStarList(t *testing.T) {
	p, err := ParseJSON("x.json", []byte(`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":["*"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := p.Statements[0].Principals
	if len(got) != 1 || got[0].Kind != "Any" {
		t.Fatalf("principals: %#v", got)
	}
}

func TestUndecodableActionAndConditionAreErrors(t *testing.T) {
	cases := []string{
		`"Action":5,"Principal":"*"`,
		`"Action":["sts:AssumeRole",5],"Principal":"*"`,
		`"Action":"sts:AssumeRole","Principal":"*","Condition":"oops"`,
		`"Action":"sts:AssumeRole","Principal":"*","Condition":{"StringEquals":"oops"}`,
		`"Action":"sts:AssumeRole","Principal":"*","Condition":{"StringEquals":{"k":{"a":1}}}`,
	}
	for _, c := range cases {
		if _, err := ParseJSON("x.json", []byte(`{"Statement":{"Effect":"Allow",`+c+`}}`)); err == nil {
			t.Fatalf("%s was accepted", c)
		}
	}
}

func TestDuplicateKeysAndDeepNestingAreErrors(t *testing.T) {
	dup := `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"},"Statement":{"Effect":"Deny"}}`
	if _, err := ParseJSON("x.json", []byte(dup)); err == nil {
		t.Fatal("duplicate Statement key was accepted")
	}
	dupInner := `{"Statement":{"Effect":"Allow","Effect":"Deny","Action":"sts:AssumeRole","Principal":"*"}}`
	if _, err := ParseJSON("x.json", []byte(dupInner)); err == nil {
		t.Fatal("duplicate Effect key was accepted")
	}
	deep := `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"},"x":` + strings.Repeat("[", 100) + strings.Repeat("]", 100) + `}`
	if _, err := ParseJSON("x.json", []byte(deep)); err == nil {
		t.Fatal("100-deep nesting was accepted")
	}
}

func TestConditionsKeepFileOrderAndOperator(t *testing.T) {
	doc := `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*","Condition":{"StringLike":{"b:k":["v1","v2"],"a:k":true},"ForAnyValue:StringEquals":{"c:k":5}}}}`
	p, err := ParseJSON("x.json", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got := p.Statements[0].Conditions
	want := []Condition{
		{"StringLike", "b:k", []string{"v1", "v2"}},
		{"StringLike", "a:k", []string{"true"}},
		{"ForAnyValue:StringEquals", "c:k", []string{"5"}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %#v", got)
	}
	for i := range want {
		if got[i].Operator != want[i].Operator || got[i].Key != want[i].Key || strings.Join(got[i].Values, ",") != strings.Join(want[i].Values, ",") {
			t.Fatalf("condition %d: got %#v want %#v", i, got[i], want[i])
		}
	}
}
