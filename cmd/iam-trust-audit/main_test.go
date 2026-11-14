package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

func TestExitCodesStep2(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(strings.Repeat(" ", (1<<20)+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"Statement"`), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		file string
		want int
	}{
		{"empty statement", fixture("empty-statement.json"), 2},
		{"invalid json", bad, 2},
		{"fifo", fifo, 2},
		{"oversized", big, 2},
		{"dev zero", "/dev/zero", 2},
		{"missing file", filepath.Join(dir, "nope.json"), 2},
		{"finding", fixture("sub-question-mark.json"), 1},
		{"deny only", fixture("deny-statement.json"), 0},
		{"sourceip only pass", fixture("sourceip-only-pass.json"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, bin, tc.file).CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("timed out\n%s", out)
			}
			if got := exitCode(err); got != tc.want {
				t.Fatalf("exit %d, want %d\n%s", got, tc.want, out)
			}
		})
	}
}
