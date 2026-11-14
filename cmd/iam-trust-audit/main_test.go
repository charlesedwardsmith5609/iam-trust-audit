package main

import (
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
