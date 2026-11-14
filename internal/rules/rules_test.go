package rules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
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

func ids(findings []Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			out = append(out, f.ID)
		}
	}
	sort.Strings(out)
	return out
}

func sameIDs(got []Finding, want []string) bool {
	g := ids(got)
	w := append([]string{}, want...)
	sort.Strings(w)
	return strings.Join(g, ",") == strings.Join(w, ",")
}

func TestStep1Fixtures(t *testing.T) {
	cases := []struct {
		file string
		want []string
	}{
		{"notprincipal-allow.json", []string{"IAM-PRINCIPAL-WILDCARD"}},
		{"deny-notprincipal.json", nil},
		{"notaction-cross-account.json", []string{"IAM-EXTERNAL-ID-MISSING", "IAM-VENDOR-NETWORK-MISSING"}},
		{"action-wildcard-sts.json", []string{"IAM-EXTERNAL-ID-MISSING", "IAM-VENDOR-NETWORK-MISSING"}},
		{"bare-account-id.json", []string{"IAM-EXTERNAL-ID-MISSING", "IAM-VENDOR-NETWORK-MISSING"}},
		{"numeric-account-id.json", []string{"IAM-EXTERNAL-ID-MISSING", "IAM-VENDOR-NETWORK-MISSING"}},
		{"tf-jsonencode.tf", []string{"IAM-UNPARSED"}},
		{"tf-data-source.tf", []string{"IAM-UNPARSED"}},
		{"tf-unterminated.tf", []string{"IAM-UNPARSED"}},
		{"tf-indented-heredoc.tf", []string{"IAM-PRINCIPAL-WILDCARD"}},
		{"tf-multi-role.tf", []string{"IAM-PRINCIPAL-WILDCARD"}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			policies, err := parse.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			got := Evaluate(policies)
			if !sameIDs(got, tc.want) {
				t.Fatalf("want %v, got %#v", tc.want, got)
			}
		})
	}
}

func TestMultiRoleFindingNamesSecondRole(t *testing.T) {
	policies, err := parse.ReadFile(filepath.Join("testdata", "tf-multi-role.tf"))
	if err != nil {
		t.Fatal(err)
	}
	got := Evaluate(policies)
	if len(got) != 1 || !strings.Contains(got[0].File, "tf-multi-role.tf") || !strings.Contains(got[0].File, "second") {
		t.Fatalf("finding should name the file and the second role: %#v", got)
	}
}

func TestUnparsedFindingIsHighAndNamed(t *testing.T) {
	policies := []parse.Policy{{File: "x.tf", Label: "line 7", Unparsed: []parse.Unparsed{{Line: 7, Reason: "jsonencode"}}}}
	got := Evaluate(policies)
	if len(got) != 1 || got[0].ID != "IAM-UNPARSED" || got[0].Severity != "high" {
		t.Fatalf("got %#v", got)
	}
	if !strings.Contains(got[0].File, "x.tf") || !strings.Contains(got[0].File, "line 7") {
		t.Fatalf("file should name path and label: %q", got[0].File)
	}
}

func evalDoc(t *testing.T, doc string) []Finding {
	t.Helper()
	policy, err := parse.ParseJSON("inline.json", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return Evaluate([]parse.Policy{policy})
}

func TestActionMatching(t *testing.T) {
	account := `"Principal":{"AWS":"arn:aws:iam::111122223333:root"}`
	cases := []struct {
		name string
		stmt string
		want bool // true: cross-account findings expected
	}{
		{"sts star", `"Action":"sts:*"`, true},
		{"star", `"Action":"*"`, true},
		{"mixed case", `"Action":"STS:assumerole"`, true},
		{"prefix glob", `"Action":"sts:Assume*"`, true},
		{"question mark", `"Action":"sts:AssumeRol?"`, true},
		{"list", `"Action":["s3:GetObject","sts:AssumeRole"]`, true},
		{"sts Get glob", `"Action":"sts:Get*"`, false},
		{"s3 star", `"Action":"s3:*"`, false},
		{"notaction excludes assume", `"NotAction":"sts:AssumeRole"`, false},
		{"notaction glob excludes assume", `"NotAction":"sts:Assume*"`, false},
		{"notaction other", `"NotAction":"s3:*"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalDoc(t, `{"Statement":{"Effect":"Allow",`+tc.stmt+`,`+account+`}}`)
			has := false
			for _, f := range got {
				if f.ID == "IAM-EXTERNAL-ID-MISSING" {
					has = true
				}
			}
			if has != tc.want {
				t.Fatalf("want ext-id finding %v, got %#v", tc.want, got)
			}
		})
	}
}

func TestOIDCWithWildcardAction(t *testing.T) {
	fed := `"Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}`
	for _, action := range []string{`"sts:*"`, `"*"`, `"sts:AssumeRoleWithWebIdentity"`, `"STS:ASSUMEROLEWITHWEBIDENTITY"`} {
		got := evalDoc(t, `{"Statement":{"Effect":"Allow","Action":`+action+`,`+fed+`}}`)
		if !sameIDs(got, []string{"IAM-OIDC-SUB-MISSING"}) {
			t.Fatalf("action %s: %#v", action, got)
		}
	}
}

func TestAccountIDForms(t *testing.T) {
	cases := []struct {
		principal string
		want      bool
	}{
		{`"111122223333"`, true},
		{`111122223333`, true},
		{`[111122223333]`, true},
		{`"arn:aws:iam::111122223333:root"`, true},
		{`"11112222333"`, false},
		{`"1111222233334"`, false},
		{`"arn:aws:sts::111122223333:assumed-role/x/y"`, false},
	}
	for _, tc := range cases {
		got := evalDoc(t, `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":`+tc.principal+`}}}`)
		has := false
		for _, f := range got {
			if f.ID == "IAM-EXTERNAL-ID-MISSING" {
				has = true
			}
		}
		if has != tc.want {
			t.Fatalf("principal %s: want %v, got %#v", tc.principal, tc.want, got)
		}
	}
}
