# Step 1: HIGH findings (review findings 1-7)

Covers: 1, 2, 3, 4, 5, 6, 7. Decisions: D5, D12, D14. Patterns: loud on the unknown, structure not regex, normalize before matching, negative tests per rule.

Assumption: finding 7's "undecodable principal is an error" is done here for Principal only. Undecodable Action and Condition, and empty Statement (finding 12) are in step 2.

## Types

- `parse.Policy` gains `Unparsed []Unparsed`. `Unparsed{Line int, Reason string}` marks a `.tf` `assume_role_policy` that could not be read as a JSON heredoc.
- `parse.Policy.File` stays the path. New field `Label string` holds the resource name or `line N` for `.tf` policies. One `Policy` per `assume_role_policy` found.
- `parse.Statement` gains `NotActions []string`, `NotPrincipals []Principal`. `Principal.Value` for a numeric `AWS` value is the decimal string.
- `rules.Finding` gains no field; `File` carries `path (label)` for `.tf`. New rule id `IAM-UNPARSED`, severity high, one finding per unparsed policy. `rules.Evaluate` emits it from `Policy.Unparsed`.
- `parse.principals` returns `([]Principal, error)`. A principal that is not a string, a string list or a number list is an error, which `ReadFile` returns (exit 2).
- Replace `heredocJSON` with `findAssumeRolePolicies(data) []tfPolicy`. It scans line by line. For each line containing `assume_role_policy` followed by `=`, it requires `<<` or `<<-` on that same line. The terminator is the first later line where `strings.TrimSpace(line) == name`. Any other value form (`jsonencode(`, `data.`, a quoted string, missing terminator) becomes `Unparsed`.
- `rules` helper `actionMatches(pattern, action string) bool`: lowercase both, glob with `*` and `?` (own small matcher, no regex). Used by `oidc`, `crossAccount`, and NotAction handling.
- Cross-account principal test: `AWS` kind and the value is an ARN containing `:iam::` or matches `^[0-9]{12}$` (checked by hand, no regex needed).
- `Allow` with any `NotPrincipal` yields `IAM-PRINCIPAL-WILDCARD` (high). `NotAction`: the statement is treated as matching `sts:AssumeRole` and `sts:AssumeRoleWithWebIdentity` unless a NotAction pattern matches that action.

## Ownership

No shared state. Parsing and evaluation are pure functions on values owned by the single `main` goroutine. No goroutines, no mutex.

## Tests (natural language, written failing first)

Parse (internal/parse):
1. A `.tf` with `assume_role_policy = jsonencode({...Principal = "*"...})` returns one Policy with one Unparsed entry (finding 1).
2. A `.tf` with `assume_role_policy = data.aws_iam_policy_document.x.json` returns an Unparsed entry.
3. A `.tf` with a heredoc and no terminator returns an Unparsed entry.
4. A `<<-EOT` heredoc with an indented body and an indented terminator parses (finding 2). A `<<POLICY` heredoc still parses.
5. A `.tf` with two roles returns two Policies, with the resource label or line in each (finding 3). The second role's wildcard principal is found.
6. A `<<` appearing in a later, unrelated resource does not get used for an earlier `assume_role_policy = jsonencode(...)` (finding 4).
7. `{"AWS":111122223333}` and `{"AWS":[111122223333]}` become principal value `111122223333` (finding 7). `{"AWS":{"a":1}}` and `Principal: 5` return an error.
8. NotPrincipal and NotAction are parsed into the new fields (finding 6).

Rules (internal/rules), one fail fixture and one pass fixture each, plus near-miss tables:
9. `Allow` plus `NotPrincipal` is `IAM-PRINCIPAL-WILDCARD`. `Deny` plus `NotPrincipal` is not flagged.
10. `NotAction` that excludes `sts:AssumeRole` is not cross-account; `NotAction: s3:*` with an account principal is cross-account and missing ExternalId.
11. Actions `sts:*`, `*`, `STS:assumerole`, `sts:Assume*`, `sts:AssumeRol?` on an account principal give `IAM-EXTERNAL-ID-MISSING`. `sts:Get*` and `s3:*` do not.
12. `sts:*` / `*` with an OIDC federated principal and no `sub` gives `IAM-OIDC-SUB-MISSING`.
13. A bare `"111122223333"` principal, a numeric one, and an `arn:aws:iam::111122223333:root` all give `IAM-EXTERNAL-ID-MISSING`. An 11-digit and a 13-digit string do not.
14. `Evaluate` on a Policy with Unparsed yields one high `IAM-UNPARSED` finding naming path and label.

CLI (cmd/iam-trust-audit), built binary, exact exit codes with `ExitError.ExitCode()`:
15. `.tf` with jsonencode wildcard: exit 1 and output contains `IAM-UNPARSED`.
16. `.tf` with invalid JSON inside a heredoc: exit 2.
17. Existing pass fixture: exit 0.

## Files

- internal/parse/parse.go
- internal/parse/parse_test.go
- internal/rules/rules.go
- internal/rules/rules_test.go
- internal/rules/testdata/notprincipal-allow.json
- internal/rules/testdata/notaction-cross-account.json
- internal/rules/testdata/action-wildcard-sts.json
- internal/rules/testdata/bare-account-id.json
- internal/rules/testdata/numeric-account-id.json
- internal/rules/testdata/deny-notprincipal.json
- internal/rules/testdata/tf-jsonencode.tf
- internal/rules/testdata/tf-data-source.tf
- internal/rules/testdata/tf-indented-heredoc.tf
- internal/rules/testdata/tf-multi-role.tf
- internal/rules/testdata/tf-unterminated.tf
- internal/rules/testdata/tf-bad-json-heredoc.tf
- cmd/iam-trust-audit/main_test.go
