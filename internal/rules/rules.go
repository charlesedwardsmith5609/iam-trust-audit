// Package rules flags risky IAM trust statements.
package rules

import (
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
		for _, statement := range policy.Statements {
			if !allows(statement) {
				continue
			}
			out = append(out, principals(policy.File, statement)...)
			if oidc(statement) {
				out = append(out, subCondition(policy.File, statement)...)
			}
			if crossAccount(statement) {
				out = append(out, externalID(policy.File, statement)...)
				out = append(out, vendorNetwork(policy.File, statement)...)
			}
		}
	}
	return out
}

func allows(statement parse.Statement) bool {
	return statement.Effect == "" || strings.EqualFold(statement.Effect, "Allow")
}

func principals(file string, statement parse.Statement) []Finding {
	for _, principal := range statement.Principals {
		if principal.Kind == "Any" || strings.Contains(principal.Value, "*") {
			return []Finding{{
				ID:        "IAM-PRINCIPAL-WILDCARD",
				Severity:  "high",
				File:      file,
				Statement: statement.Index,
				Fix:       "Replace the wildcard principal with a specific account, role, or OIDC subject.",
			}}
		}
	}
	return nil
}

func oidc(statement parse.Statement) bool {
	for _, action := range statement.Actions {
		if strings.Contains(action, "AssumeRoleWithWebIdentity") {
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
	if oidc(statement) {
		return false
	}
	for _, action := range statement.Actions {
		if action != "sts:AssumeRole" && !strings.HasSuffix(action, ":AssumeRole") {
			continue
		}
		for _, principal := range statement.Principals {
			if principal.Kind == "AWS" && strings.Contains(principal.Value, ":iam::") {
				return true
			}
		}
	}
	return false
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
