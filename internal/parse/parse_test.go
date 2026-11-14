package parse

import (
	"os"
	"path/filepath"
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
