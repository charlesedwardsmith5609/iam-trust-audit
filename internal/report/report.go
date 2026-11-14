// Package report prints findings as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"iam-trust-audit/internal/rules"
)

// Rank returns 1, 2, or 3. Unknown severities are treated as high.
func Rank(severity string) int {
	switch strings.ToLower(severity) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 3
	}
}

// Exceeds is true when a finding is at or above failOn.
func Exceeds(findings []rules.Finding, failOn string) bool {
	limit := Rank(failOn)
	for _, finding := range findings {
		if Rank(finding.Severity) >= limit {
			return true
		}
	}
	return false
}

// Text writes one block per finding. It does not write the policy body.
func Text(w io.Writer, findings []rules.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "no findings")
		return err
	}
	for _, finding := range findings {
		if _, err := fmt.Fprintf(w, "%s %s %q statement %d\n  fix: %s\n", finding.Severity, finding.ID, finding.File, finding.Statement, finding.Fix); err != nil {
			return err
		}
	}
	return nil
}

// JSON writes the findings array and the fail-on level.
func JSON(w io.Writer, findings []rules.Finding, failOn string) error {
	if findings == nil {
		findings = []rules.Finding{}
	}
	payload := struct {
		FailOn   string          `json:"fail_on"`
		Findings []rules.Finding `json:"findings"`
	}{FailOn: failOn, Findings: findings}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
