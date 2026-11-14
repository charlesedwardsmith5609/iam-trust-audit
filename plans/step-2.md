# Step 2: MEDIUM findings (review findings 8-13)

Covers: 8, 9, 10, 11, 12, 13. Decisions: D5, D12. Patterns: bounded reads, structure not regex, decode once, exact exit-code tests, negative tests per rule.

Depends on step 1 types (`Policy.Unparsed`, `NotActions`). Do not start before step 1 lands.

Assumptions:
- Finding 8's "flag * in PrincipalOrgID and ExternalId" reuses `IAM-VENDOR-NETWORK-MISSING` (medium) for OrgID/SourceIp and `IAM-EXTERNAL-ID-MISSING` (high) for ExternalId. No new rule ids, so the rule list in REQUIREMENTS.md stays valid.
- D3 (second condition needs a valid SourceIp or SourceVpce, OrgID additive only) belongs to platform-templates, not this repo. `aws:PrincipalOrgID` still satisfies `IAM-VENDOR-NETWORK-MISSING` here unless it contains `*`. List as a Suggestion.
- Finding 9 `aud` is documented as unchecked in the threat model; the code change is `?` in `sub` plus restricting the `sub` key to the provider-qualified form. "sub key matches any *:sub provider" is addressed by requiring the key's provider prefix to match the Federated principal's provider host when it can be determined, otherwise the key counts. This is the more restrictive reading.

## Types

- `parse.Statement.Conditions` becomes `[]Condition{Operator string, Key string, Values []string}` in file order, so operator semantics are kept and output is deterministic. Operator is stored as written; helpers lowercase it.
- `parse.ReadFile` uses `readBounded` from `.review/shared-patterns.md`: `os.OpenFile(path, O_RDONLY|O_NOFOLLOW|O_NONBLOCK)`, `f.Stat()`, `IsRegular()`, `io.LimitReader(f, MaxBytes+1)`. The Lstat path is removed.
- Decode errors: `stringList`, `conditions` and Statement decoding return errors instead of nil. Empty array, `null`, or a missing `Statement` is an error. `Principal: ["*"]` is decoded as a list and treated as `Any` (it is a failure to decode a bare list, so decode it as one).
- Duplicate keys and nesting deeper than 64 are rejected by one `json.Decoder.Token()` pre-walk (`checkJSON(data) error`).
- `rules`: `positiveOperator(op string) bool` accepts `stringequals`, `stringlike`, `foranyvalue:stringequals`, `foranyvalue:stringlike`, case-insensitive, optional `IfExists` suffix rejected. `conditionValues` returns values only from positive operators and compares the key with `strings.EqualFold`.
- `isWildcard(s)`: contains `*` or `?`. `anyCIDR(s)`: `0.0.0.0/0` or `::/0` (parsed with `net/netip`).

## Ownership

No shared state; same single-goroutine model as step 1.

## Tests (natural language, written failing first)

Parse:
1. `/dev/zero` and a FIFO created with `syscall.Mkfifo` are rejected with an error and do not hang (test has a 5 s timeout via goroutine and `select`) (finding 11).
2. A file of MaxBytes+1 bytes is rejected; exactly MaxBytes is read.
3. A symlink as the last component is rejected.
4. `{"Statement":[]}`, `{"Statement":null}`, `{"Statement":{}}`-less docs: error (finding 12).
5. `Principal: ["*"]` becomes a wildcard principal. Undecodable `Action` (a number) and undecodable `Condition` (a string) return an error.
6. Duplicate `Statement` key and a 100-deep nested document return an error.

Rules, with pass and fail fixtures and near-miss tables:
7. `StringNotEquals` on `sub` gives `IAM-OIDC-SUB-MISSING`; `ForAllValues:StringEquals` and `Null` on ExternalId give `IAM-EXTERNAL-ID-MISSING`; `StringEquals`, `StringLike`, `ForAnyValue:StringEquals` pass (finding 8).
8. `aws:SourceIp` of `0.0.0.0/0` or `::/0` still gives `IAM-VENDOR-NETWORK-MISSING`; a real CIDR alone passes (SourceIp-only pass). `*` in PrincipalOrgID gives the finding. `*` in ExternalId gives `IAM-EXTERNAL-ID-MISSING`.
9. `sub` of `repo:org/r:ref:refs/heads/ma?n` gives `IAM-OIDC-SUB-WILDCARD` (finding 9). A `sub` key under another provider host than the Federated principal is not accepted. Missing `aud` is not a finding (documented).
10. `sts:externalid` and `STS:ExternalId` satisfy the ExternalId rule (finding 10).
11. Deny statement is not flagged; mixed Allow/Deny statements flag only the Allow; `jsonencode` and multi-role `.tf` covered in step 1 and reused here (finding 13).
12. Every rule id (`PRINCIPAL-WILDCARD`, `EXTERNAL-ID-MISSING`, `VENDOR-NETWORK-MISSING`, `OIDC-SUB-MISSING`, `OIDC-SUB-WILDCARD`, `UNPARSED`) has at least one pass and one fail fixture; a test lists the rule ids and fails if one lacks a fixture.

CLI:
13. Exit 2 (exact) for empty Statement, invalid JSON, FIFO, oversized file, `/dev/zero`. Exit 1 (exact) for a finding. Exit 0 for pass. The tests unwrap `*exec.ExitError` and compare `ExitCode()`; plain `err != nil` is not accepted.

## Files

- internal/parse/parse.go
- internal/parse/parse_test.go
- internal/rules/rules.go
- internal/rules/rules_test.go
- internal/rules/testdata/sub-string-not-equals.json
- internal/rules/testdata/externalid-for-all-values.json
- internal/rules/testdata/externalid-null.json
- internal/rules/testdata/externalid-lowercase-key.json
- internal/rules/testdata/sourceip-open.json
- internal/rules/testdata/sourceip-only-pass.json
- internal/rules/testdata/orgid-wildcard.json
- internal/rules/testdata/externalid-wildcard.json
- internal/rules/testdata/sub-question-mark.json
- internal/rules/testdata/sub-other-provider.json
- internal/rules/testdata/deny-statement.json
- internal/rules/testdata/mixed-statements.json
- internal/rules/testdata/empty-statement.json
- internal/rules/testdata/principal-star-list.json
- cmd/iam-trust-audit/main_test.go
- docs/threat-model.md
