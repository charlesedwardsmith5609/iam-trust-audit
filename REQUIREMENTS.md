# Requirements

`iam-trust-audit` reads IAM role trust policies and reports risky trust. It does not call AWS and it does not change any account.

## Inputs

- JSON policy documents.
- Terraform files that set `assume_role_policy` to a JSON heredoc. `jsonencode({...})` HCL is not parsed. That form is named in the threat model as unsupported rather than guessed.

## Rules

Each finding has an id, a severity (`low`, `medium`, or `high`), a location, and a fix hint.

- Wildcard principals.
- Cross-account `sts:AssumeRole` without `sts:ExternalId`.
- OIDC trust, including `token.actions.githubusercontent.com`, with a missing `sub` or a `sub` that contains `*`.
- Cross-account `sts:AssumeRole` without `aws:SourceIp` and without `aws:PrincipalOrgID`.

A statement whose principal is an AWS account ARN is treated as cross-account. This tool does not know the home account id.

## Output

Human text and JSON. Exit non-zero when a finding is at or above `--fail-on` (default `low`, so any finding fails). Exit 2 when a selected file cannot be read or parsed.

## Tests

Fixtures for a passing policy and a failing policy for every rule. Tests do not use the network.

## Review fixes 2026-11-14

Source: `.review/findings.md`, decisions in `.review/DECISIONS.md`. Standard library only.

- Unknown input is loud (D5): a `.tf` file whose `assume_role_policy` cannot be read as a JSON heredoc (for example `jsonencode`, a data source reference, or a heredoc with no terminator) produces a HIGH `IAM-UNPARSED` finding and exit 1. Invalid JSON, unreadable, oversized or non-regular files exit 2. An empty or null `Statement`, and an undecodable `Principal`, `Action` or `Condition`, exit 2.
- Every `assume_role_policy` in a `.tf` file is audited, including `<<-` heredocs. The `<<` must be on the same line as the `=`.
- `NotPrincipal` and `NotAction` are parsed. `Allow` with `NotPrincipal` is a wildcard principal. Action matching is case-insensitive and honors `*` and `?`. A bare 12-digit account id, or a numeric one, is a cross-account principal.
- Condition operators: only positive operators (`StringEquals`, `StringLike`, `ForAnyValue:` variants) satisfy `sub` and `sts:ExternalId`. `StringNotEquals`, `ForAllValues:` and `Null` do not. `aws:SourceIp` of `0.0.0.0/0` or `::/0`, and `*` in `aws:PrincipalOrgID` or ExternalId, are findings. Condition keys match case-insensitively. A `sub` containing `?` is a wildcard. The `sub` check and the missing `aud` check are described in the threat model.
- Files are read with one open, `Stat`, a regular-file check and a 1 MiB bounded read.
- Output: file names are printed with `%q`. `--fail-on` is lowercased once and then validated. `aws iam get-role` output and URL-encoded documents are supported or documented. `go.mod` follows D10. CI checkout sets `persist-credentials: false`.
- Tests: one pass and one fail fixture per rule, and the CLI test asserts exit code 1 versus 2 exactly.
