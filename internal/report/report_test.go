package report

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"iam-trust-audit/internal/rules"
)

func TestTextAndJSONOmitPolicyBody(t *testing.T) {
	findings := []rules.Finding{{
		ID:        "IAM-OIDC-SUB-WILDCARD",
		Severity:  "high",
		File:      "role.json",
		Statement: 0,
		Fix:       "Replace the wildcard sub.",
	}}
	var text bytes.Buffer
	if err := Text(&text, findings); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "IAM-OIDC-SUB-WILDCARD") || strings.Contains(text.String(), "AKIA") {
		t.Fatalf("text: %s", text.String())
	}
	var js bytes.Buffer
	if err := JSON(&js, findings, "low"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"fail_on": "low"`) {
		t.Fatalf("json: %s", js.String())
	}
	if !Exceeds(findings, "high") || Exceeds(findings, "low") == false {
		t.Fatal("severity gate")
	}
	if Exceeds([]rules.Finding{{Severity: "low"}}, "high") {
		t.Fatal("low finding should not fail a high gate")
	}
}

func TestTextQuotesFileNames(t *testing.T) {
	name := "evil\n\x1b[31mred.json"
	var buf bytes.Buffer
	findings := []rules.Finding{{ID: "IAM-X", Severity: "high", File: name, Statement: 0, Fix: "fix it"}}
	if err := Text(&buf, findings); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("raw escape in output: %q", out)
	}
	if lines := strings.Split(strings.TrimRight(out, "\n"), "\n"); len(lines) != 2 {
		t.Fatalf("want 2 lines (finding and fix), got %d: %q", len(lines), out)
	}
	if !strings.Contains(out, strconv.Quote(name)) {
		t.Fatalf("file name not quoted: %q", out)
	}
}
