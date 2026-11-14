package parse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
