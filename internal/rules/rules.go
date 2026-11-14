// Package rules flags risky IAM trust statements.
package rules

import (
	"fmt"
	"strings"

	"iam-trust-audit/internal/parse"
)

// Finding is one rule result. It does not include the policy text.
type Finding struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	File      string `json:"file"`
	Statement int    `json:"statement"`
	Fix       string `json:"fix"`
}

// Evaluate applies every rule to policies.
func Evaluate(policies []parse.Policy) []Finding {
	var out []Finding
	for _, policy := range policies {
		name := fileName(policy)
		for _, u := range policy.Unparsed {
			out = append(out, Finding{
				ID:       "IAM-UNPARSED",
				Severity: "high",
				File:     name,
				Fix:      fmt.Sprintf("Line %d: %s. Write the trust policy as a JSON heredoc or audit it another way.", u.Line, u.Reason),
			})
		}
		for _, statement := range policy.Statements {
			if !allows(statement) {
				continue
			}
			out = append(out, principals(name, statement)...)
			if oidc(statement) {
				out = append(out, subCondition(name, statement)...)
			}
			if crossAccount(statement) {
				out = append(out, externalID(name, statement)...)
				out = append(out, vendorNetwork(name, statement)...)
			}
		}
	}
	return out
}

func allows(statement parse.Statement) bool {
	return statement.Effect == "" || strings.EqualFold(statement.Effect, "Allow")
}

func fileName(policy parse.Policy) string {
	if policy.Label == "" {
		return policy.File
	}
	return policy.File + " (" + policy.Label + ")"
}

func principals(file string, statement parse.Statement) []Finding {
	wildcard := len(statement.NotPrincipals) > 0
	for _, principal := range statement.Principals {
		if principal.Kind == "Any" || strings.Contains(principal.Value, "*") {
			wildcard = true
		}
	}
	if !wildcard {
		return nil
	}
	return []Finding{{
		ID:        "IAM-PRINCIPAL-WILDCARD",
		Severity:  "high",
		File:      file,
		Statement: statement.Index,
		Fix:       "Replace the wildcard or NotPrincipal with a specific account, role, or OIDC subject.",
	}}
}

// actionMatches compares an IAM action pattern with an action, ignoring case.
// * matches any run of characters and ? matches one character.
func actionMatches(pattern, action string) bool {
	p, a := []rune(strings.ToLower(pattern)), []rune(strings.ToLower(action))
	pi, ai, star, mark := 0, 0, -1, 0
	for ai < len(a) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == a[ai]) && p[pi] != '*':
			pi++
			ai++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ai
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ai = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// appliesTo reports whether the statement's Action or NotAction covers action.
func appliesTo(statement parse.Statement, action string) bool {
	if len(statement.NotActions) > 0 {
		for _, pattern := range statement.NotActions {
			if actionMatches(pattern, action) {
				return false
			}
		}
		return true
	}
	for _, pattern := range statement.Actions {
		if actionMatches(pattern, action) {
			return true
		}
	}
	return false
}

func oidc(statement parse.Statement) bool {
	// Only an exact action name marks OIDC on its own. A wildcard action such as
	// sts:* also covers AssumeRole, so it needs a federated OIDC principal.
	for _, action := range statement.Actions {
		if strings.EqualFold(action, "sts:AssumeRoleWithWebIdentity") {
			return true
		}
	}
	for _, principal := range statement.Principals {
		if principal.Kind == "Federated" && (strings.Contains(principal.Value, "oidc-provider/") || strings.Contains(principal.Value, "token.actions.githubusercontent.com")) {
			return true
		}
	}
	return false
}

func subCondition(file string, statement parse.Statement) []Finding {
	values := conditionValues(statement, "sub")
	if len(values) == 0 {
		return []Finding{{
			ID:        "IAM-OIDC-SUB-MISSING",
			Severity:  "high",
			File:      file,
			Statement: statement.Index,
			Fix:       "Set a StringEquals sub to one repository or one service account. Do not omit sub.",
		}}
	}
	for _, value := range values {
		if value == "" || strings.Contains(value, "*") {
			return []Finding{{
				ID:        "IAM-OIDC-SUB-WILDCARD",
				Severity:  "high",
				File:      file,
				Statement: statement.Index,
				Fix:       "Replace the wildcard sub with a specific repository ref or service account.",
			}}
		}
	}
	return nil
}

func crossAccount(statement parse.Statement) bool {
	if oidc(statement) || !appliesTo(statement, "sts:AssumeRole") {
		return false
	}
	for _, principal := range statement.Principals {
		if principal.Kind == "AWS" && (strings.Contains(principal.Value, ":iam::") || accountID(principal.Value)) {
			return true
		}
	}
	return false
}

func accountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func externalID(file string, statement parse.Statement) []Finding {
	if len(conditionValues(statement, "sts:ExternalId")) > 0 {
		return nil
	}
	return []Finding{{
		ID:        "IAM-EXTERNAL-ID-MISSING",
		Severity:  "high",
		File:      file,
		Statement: statement.Index,
		Fix:       "Require sts:ExternalId on this cross-account trust.",
	}}
}

func vendorNetwork(file string, statement parse.Statement) []Finding {
	if len(conditionValues(statement, "aws:SourceIp")) > 0 || len(conditionValues(statement, "aws:PrincipalOrgID")) > 0 {
		return nil
	}
	return []Finding{{
		ID:        "IAM-VENDOR-NETWORK-MISSING",
		Severity:  "medium",
		File:      file,
		Statement: statement.Index,
		Fix:       "Require aws:SourceIp or aws:PrincipalOrgID on this cross-account trust.",
	}}
}

func conditionValues(statement parse.Statement, suffix string) []string {
	var out []string
	for _, keys := range statement.Conditions {
		for key, values := range keys {
			if key == suffix || strings.HasSuffix(key, ":"+suffix) {
				out = append(out, values...)
			}
		}
	}
	return out
}
