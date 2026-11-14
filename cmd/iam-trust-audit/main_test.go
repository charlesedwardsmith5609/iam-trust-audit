package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "iam-trust-audit")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	pass := filepath.Join("..", "..", "internal", "rules", "testdata", "pass.json")
	bad := filepath.Join("..", "..", "internal", "rules", "testdata", "oidc-sub-wildcard.json")

	ok := exec.Command(bin, "--format", "json", pass)
	out, err := ok.CombinedOutput()
	if err != nil {
		t.Fatalf("pass: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `"findings": []`) {
		t.Fatalf("json: %s", out)
	}

	fail := exec.Command(bin, "--format", "text", bad)
	out, err = fail.CombinedOutput()
	if err == nil {
		t.Fatal("wildcard sub should exit non-zero")
	}
	if !strings.Contains(string(out), "IAM-OIDC-SUB-WILDCARD") {
		t.Fatalf("text: %s", out)
	}

	medium := exec.Command(bin, "--fail-on", "high", filepath.Join("..", "..", "internal", "rules", "testdata", "missing-vendor-network.json"))
	if err := medium.Run(); err != nil {
		t.Fatal("medium finding should pass a high gate")
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func buildBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "iam-trust-audit")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func fixture(name string) string {
	return filepath.Join("..", "..", "internal", "rules", "testdata", name)
}

func TestExitCodesStep1(t *testing.T) {
	bin := buildBin(t)
	cases := []struct {
		name     string
		file     string
		wantCode int
		wantOut  string
	}{
		{"jsonencode wildcard", "tf-jsonencode.tf", 1, "IAM-UNPARSED"},
		{"data source", "tf-data-source.tf", 1, "IAM-UNPARSED"},
		{"bad json heredoc", "tf-bad-json-heredoc.tf", 2, ""},
		{"multi role", "tf-multi-role.tf", 1, "IAM-PRINCIPAL-WILDCARD"},
		{"pass", "pass.json", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command(bin, fixture(tc.file)).CombinedOutput()
			if got := exitCode(err); got != tc.wantCode {
				t.Fatalf("exit %d, want %d\n%s", got, tc.wantCode, out)
			}
			if !strings.Contains(string(out), tc.wantOut) {
				t.Fatalf("output lacks %q:\n%s", tc.wantOut, out)
			}
		})
	}
}
