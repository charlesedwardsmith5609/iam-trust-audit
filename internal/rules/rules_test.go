package rules

import (
	"os"
	"path/filepath"
	"testing"

	"iam-trust-audit/internal/parse"
)

func TestFixtures(t *testing.T) {
	cases := []struct {
		file string
		want string
	}{
		{"pass.json", ""},
		{"wildcard-principal.json", "IAM-PRINCIPAL-WILDCARD"},
		{"missing-external-id.json", "IAM-EXTERNAL-ID-MISSING"},
		{"missing-vendor-network.json", "IAM-VENDOR-NETWORK-MISSING"},
		{"oidc-sub-missing.json", "IAM-OIDC-SUB-MISSING"},
		{"oidc-sub-wildcard.json", "IAM-OIDC-SUB-WILDCARD"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			policies, err := parse.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			got := Evaluate(policies)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("want no findings, got %#v", got)
				}
				return
			}
			found := false
			for _, finding := range got {
				if finding.ID == tc.want {
					found = true
					if finding.Fix == "" || finding.Severity == "" {
						t.Fatalf("incomplete finding: %#v", finding)
					}
				}
			}
			if !found {
				t.Fatalf("missing %s in %#v", tc.want, got)
			}
		})
	}
}

func TestPassFileExists(t *testing.T) {
	if _, err := os.Stat("testdata/pass.json"); err != nil {
		t.Fatal(err)
	}
}
