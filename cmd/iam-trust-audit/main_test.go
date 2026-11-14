package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

func TestFailOnIsNormalizedThenValidated(t *testing.T) {
	bin := buildBin(t)
	medium := fixture("missing-vendor-network.json") // one medium finding
	cases := []struct {
		level string
		want  int
	}{
		{"low", 1}, {"Medium", 1}, {"MEDIUM", 1}, {" medium ", 1},
		{"high", 0}, {"HIGH", 0}, {" high", 0}, {"High", 0},
		{"urgent", 2}, {"", 2}, {"   ", 2},
	}
	for _, tc := range cases {
		t.Run(strconv.Quote(tc.level), func(t *testing.T) {
			out, err := exec.Command(bin, "--fail-on", tc.level, medium).CombinedOutput()
			if got := exitCode(err); got != tc.want {
				t.Fatalf("exit %d, want %d\n%s", got, tc.want, out)
			}
		})
	}
	out, err := exec.Command(bin, "--format", "json", "--fail-on", "HIGH", medium).CombinedOutput()
	if exitCode(err) != 0 || !strings.Contains(string(out), `"fail_on": "high"`) {
		t.Fatalf("json should carry the normalized level: %v\n%s", err, out)
	}
}

func parseFixture(name string) string {
	return filepath.Join("..", "..", "internal", "parse", "testdata", name)
}

func TestGetRoleAndEncodedDocumentsMatchBarePolicy(t *testing.T) {
	bin := buildBin(t)
	for _, name := range []string{"policy.json", "get-role.json", "get-role-string.json", "get-role-encoded.json", "url-encoded.json"} {
		t.Run(name, func(t *testing.T) {
			out, err := exec.Command(bin, parseFixture(name)).CombinedOutput()
			if got := exitCode(err); got != 1 {
				t.Fatalf("exit %d, want 1\n%s", got, out)
			}
			if !strings.Contains(string(out), "IAM-OIDC-SUB-WILDCARD") || strings.Count(string(out), "IAM-") != 1 {
				t.Fatalf("want exactly the sub wildcard finding:\n%s", out)
			}
		})
	}
}

func TestErrorNamesThePathOnce(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{"Statement"`), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"Statement":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{parseFixture("url-encoded-bad.json"), broken, empty, filepath.Join(dir, "missing.json")} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cmd := exec.Command(bin, path)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			err := cmd.Run()
			if got := exitCode(err); got != 2 {
				t.Fatalf("exit %d, want 2\n%s", got, stderr.String())
			}
			if n := strings.Count(stderr.String(), path); n != 1 {
				t.Fatalf("path appears %d times, want 1:\n%s", n, stderr.String())
			}
		})
	}
}

func TestFileNameIsQuotedInTextOutput(t *testing.T) {
	bin := buildBin(t)
	name := filepath.Join(t.TempDir(), "evil\n\x1b[31mred.json")
	doc, err := os.ReadFile(fixture("wildcard-principal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, doc, 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command(bin, name).CombinedOutput()
	if strings.Contains(string(out), "\x1b") || !strings.Contains(string(out), "IAM-PRINCIPAL-WILDCARD") {
		t.Fatalf("output: %q", out)
	}
}

func TestCIChecksOutWithoutPersistedCredentials(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if !strings.Contains(line, "actions/checkout@") {
			continue
		}
		step := ""
		for _, next := range lines[i+1:] {
			if strings.HasPrefix(strings.TrimSpace(next), "- ") {
				break
			}
			step += next + "\n"
		}
		if !strings.Contains(step, "persist-credentials: false") {
			t.Fatalf("checkout step lacks persist-credentials: false:\n%s", line+"\n"+step)
		}
		return
	}
	t.Fatal("no checkout step found")
}

func TestGoDirectiveFollowsD10(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var goLine, toolchain string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "go ") {
			goLine = strings.TrimPrefix(line, "go ")
		}
		if strings.HasPrefix(line, "toolchain ") {
			toolchain = strings.TrimPrefix(line, "toolchain ")
		}
	}
	if !(goLine == "1.26.11" && toolchain == "") && !(goLine == "1.26" && toolchain == "go1.26.11") {
		t.Fatalf("go.mod: go %q toolchain %q", goLine, toolchain)
	}
}

func TestDecisionsHasA20261114Entry(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "DECISIONS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "2026-11-14") {
		t.Fatal("DECISIONS.md has no 2026-11-14 entry")
	}
}
