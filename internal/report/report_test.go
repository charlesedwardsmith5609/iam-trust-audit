package report

import (
	"bytes"
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
