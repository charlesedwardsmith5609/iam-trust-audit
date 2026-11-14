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
