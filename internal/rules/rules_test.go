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

func fixtureIDs(t *testing.T, file string) []string {
	t.Helper()
	policies, err := parse.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return ids(Evaluate(policies))
}

func TestStep2Fixtures(t *testing.T) {
	cases := []struct {
		file string
		want []string
	}{
		{"sub-string-not-equals.json", []string{"IAM-OIDC-SUB-MISSING"}},
		{"externalid-for-all-values.json", []string{"IAM-EXTERNAL-ID-MISSING", "IAM-VENDOR-NETWORK-MISSING"}},
		{"externalid-null.json", []string{"IAM-EXTERNAL-ID-MISSING", "IAM-VENDOR-NETWORK-MISSING"}},
		{"externalid-lowercase-key.json", nil},
		{"sourceip-open.json", []string{"IAM-VENDOR-NETWORK-MISSING"}},
		{"sourceip-open-v6.json", []string{"IAM-VENDOR-NETWORK-MISSING"}},
		{"sourceip-only-pass.json", nil},
		{"orgid-wildcard.json", []string{"IAM-VENDOR-NETWORK-MISSING"}},
		{"externalid-wildcard.json", []string{"IAM-EXTERNAL-ID-MISSING"}},
		{"sub-question-mark.json", []string{"IAM-OIDC-SUB-WILDCARD"}},
		{"sub-other-provider.json", []string{"IAM-OIDC-SUB-MISSING"}},
		{"deny-statement.json", nil},
		{"mixed-statements.json", []string{"IAM-EXTERNAL-ID-MISSING", "IAM-VENDOR-NETWORK-MISSING"}},
		{"principal-star-list.json", []string{"IAM-PRINCIPAL-WILDCARD"}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			got := fixtureIDs(t, tc.file)
			if strings.Join(got, ",") != strings.Join(sortedCopy(tc.want), ",") {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func TestMixedStatementsFlagOnlyTheAllow(t *testing.T) {
	policies, err := parse.ReadFile(filepath.Join("testdata", "mixed-statements.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Evaluate(policies) {
		if f.Statement != 1 {
			t.Fatalf("finding on the Deny statement: %#v", f)
		}
	}
}

func TestEmptyStatementFixtureIsAParseError(t *testing.T) {
	if _, err := parse.ReadFile(filepath.Join("testdata", "empty-statement.json")); err == nil {
		t.Fatal("empty Statement was accepted")
	}
}

func TestConditionOperators(t *testing.T) {
	acct := `"Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::111122223333:root"}`
	net := `"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}`
	cases := []struct {
		name      string
		condition string
		wantExtID bool
	}{
		{"StringEquals", `"StringEquals":{"sts:ExternalId":"x1"},` + net, false},
		{"StringLike", `"StringLike":{"sts:ExternalId":"x1"},` + net, false},
		{"ForAnyValue:StringEquals", `"ForAnyValue:StringEquals":{"sts:ExternalId":"x1"},` + net, false},
		{"lowercase operator", `"stringequals":{"sts:ExternalId":"x1"},` + net, false},
		{"upper-case key", `"StringEquals":{"STS:EXTERNALID":"x1"},` + net, false},
		{"StringNotEquals", `"StringNotEquals":{"sts:ExternalId":"x1"},` + net, true},
		{"ForAllValues", `"ForAllValues:StringEquals":{"sts:ExternalId":"x1"},` + net, true},
		{"IfExists", `"StringEqualsIfExists":{"sts:ExternalId":"x1"},` + net, true},
		{"Null", `"Null":{"sts:ExternalId":"false"},` + net, true},
		{"question mark value", `"StringLike":{"sts:ExternalId":"x?"},` + net, true},
		{"empty value", `"StringEquals":{"sts:ExternalId":""},` + net, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalDoc(t, `{"Statement":{"Effect":"Allow",`+acct+`,"Condition":{`+tc.condition+`}}}`)
			has := false
			for _, f := range got {
				if f.ID == "IAM-EXTERNAL-ID-MISSING" {
					has = true
				}
			}
			if has != tc.wantExtID {
				t.Fatalf("want ext-id finding %v, got %#v", tc.wantExtID, got)
			}
		})
	}
}

func TestSubOperatorAndProvider(t *testing.T) {
	fed := `"Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}`
	main := `"repo:example-org/example-repo:ref:refs/heads/main"`
	cases := []struct {
		name string
		cond string
		want []string
	}{
		{"StringEquals ok", `"StringEquals":{"token.actions.githubusercontent.com:sub":` + main + `}`, nil},
		{"StringLike ok", `"StringLike":{"token.actions.githubusercontent.com:sub":` + main + `}`, nil},
		{"ForAnyValue ok", `"ForAnyValue:StringEquals":{"token.actions.githubusercontent.com:sub":` + main + `}`, nil},
		{"key case", `"StringEquals":{"Token.Actions.GitHubUserContent.com:SUB":` + main + `}`, nil},
		{"ForAllValues", `"ForAllValues:StringEquals":{"token.actions.githubusercontent.com:sub":` + main + `}`, []string{"IAM-OIDC-SUB-MISSING"}},
		{"Null", `"Null":{"token.actions.githubusercontent.com:sub":"false"}`, []string{"IAM-OIDC-SUB-MISSING"}},
		{"question", `"StringLike":{"token.actions.githubusercontent.com:sub":"repo:o/r:ref:refs/heads/ma?n"}`, []string{"IAM-OIDC-SUB-WILDCARD"}},
		{"star", `"StringLike":{"token.actions.githubusercontent.com:sub":"repo:o/*"}`, []string{"IAM-OIDC-SUB-WILDCARD"}},
		{"other provider", `"StringEquals":{"evil.example.com:sub":` + main + `}`, []string{"IAM-OIDC-SUB-MISSING"}},
		{"aud only", `"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}`, []string{"IAM-OIDC-SUB-MISSING"}},
		{"missing aud is fine", `"StringEquals":{"token.actions.githubusercontent.com:sub":` + main + `}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ids(evalDoc(t, `{"Statement":{"Effect":"Allow",`+fed+`,"Condition":{`+tc.cond+`}}}`))
			if strings.Join(got, ",") != strings.Join(sortedCopy(tc.want), ",") {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestNetworkConditions(t *testing.T) {
	base := `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Condition":{"ForAnyValue:StringEquals":{"sts:ExternalId":"x1"},`
	cases := []struct {
		name string
		cond string
		want bool // network finding expected
	}{
		{"real cidr", `"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}}`, false},
		{"v6 cidr", `"IpAddress":{"aws:SourceIp":"2001:db8::/32"}}}}`, false},
		{"open v4", `"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}}}`, true},
		{"open v6", `"IpAddress":{"aws:SourceIp":"::/0"}}}}`, true},
		{"open among others", `"IpAddress":{"aws:SourceIp":["203.0.113.0/24","0.0.0.0/0"]}}}}`, true},
		{"NotIpAddress", `"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}}`, true},
		{"orgid", `"StringEquals":{"aws:PrincipalOrgID":"o-abc1234567"}}}}`, false},
		{"orgid star", `"StringLike":{"aws:PrincipalOrgID":"*"}}}}`, true},
		{"none", `"StringEquals":{"aws:username":"x"}}}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalDoc(t, base+tc.cond)
			has := false
			for _, f := range got {
				if f.ID == "IAM-VENDOR-NETWORK-MISSING" {
					has = true
				}
			}
			if has != tc.want {
				t.Fatalf("want network finding %v, got %#v", tc.want, got)
			}
		})
	}
}

// Every rule id needs one fixture that fails it and one that passes it.
func TestEveryRuleHasPassAndFailFixtures(t *testing.T) {
	fail := map[string]string{
		"IAM-PRINCIPAL-WILDCARD":     "wildcard-principal.json",
		"IAM-EXTERNAL-ID-MISSING":    "missing-external-id.json",
		"IAM-VENDOR-NETWORK-MISSING": "missing-vendor-network.json",
		"IAM-OIDC-SUB-MISSING":       "oidc-sub-missing.json",
		"IAM-OIDC-SUB-WILDCARD":      "oidc-sub-wildcard.json",
		"IAM-UNPARSED":               "tf-jsonencode.tf",
	}
	pass := map[string]string{
		"IAM-PRINCIPAL-WILDCARD":     "pass.json",
		"IAM-EXTERNAL-ID-MISSING":    "sourceip-only-pass.json",
		"IAM-VENDOR-NETWORK-MISSING": "sourceip-only-pass.json",
		"IAM-OIDC-SUB-MISSING":       "pass.json",
		"IAM-OIDC-SUB-WILDCARD":      "pass.json",
		"IAM-UNPARSED":               "pass.json",
	}
	for _, id := range AllIDs {
		f, p := fail[id], pass[id]
		if f == "" || p == "" {
			t.Fatalf("rule %s lacks a pass or fail fixture", id)
		}
		if !contains(fixtureIDs(t, f), id) {
			t.Errorf("%s: fixture %s does not trigger it", id, f)
		}
		if contains(fixtureIDs(t, p), id) {
			t.Errorf("%s: pass fixture %s triggers it", id, p)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
