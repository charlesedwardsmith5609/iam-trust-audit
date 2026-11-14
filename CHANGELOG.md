# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `IAM-UNPARSED` (high): a `.tf` `assume_role_policy` that is not a JSON heredoc (`jsonencode`, data source, string, unterminated heredoc) is reported instead of skipped.
- Every `assume_role_policy` in a `.tf` file is audited, including `<<-` heredocs; the finding file name carries the Terraform resource.
- Input: `aws iam get-role` output (object or string `AssumeRolePolicyDocument`) and percent-encoded policy documents.
- `NotPrincipal` and `NotAction` are parsed. `Allow` with `NotPrincipal` is a wildcard principal.
- Bare 12-digit (or numeric) account ids count as cross-account principals.
- Fixtures and tests for each rule, exact exit-code 1 versus 2 tests, and a CLI test file.
- `CHANGELOG.md`; README now documents flags, exit codes, input shapes, refusals and rules.
- Agent-pairing kit helper refreshes: `scripts/cross-review.sh`, `scripts/cross-review.ps1`, `scripts/check.sh`, `scripts/misbehavior-check.sh`, `scripts/assertion-check.sh`, `scripts/review-call.sh`. The cross-review scripts scan the request with gitleaks and send nothing if the scan cannot run.

### Changed

- Action matching is case-insensitive and honors `*` and `?`.
- Only positive condition operators (`StringEquals`, `StringLike`, `IpAddress`, with optional `ForAnyValue:`) satisfy `sub`, `sts:ExternalId`, `aws:SourceIp` and `aws:PrincipalOrgID`. `StringNotEquals`, `ForAllValues:`, `IfExists` and `Null` do not. Condition keys match case-insensitively.
- `sub` containing `?` is a wildcard; with one named Federated provider, the `sub` key must belong to it.
- Wildcard `aws:SourceIp` (`0.0.0.0/0`, `::/0`), and `*` in `aws:PrincipalOrgID` or `sts:ExternalId`, no longer satisfy their rules.
- Files are opened once with `O_NOFOLLOW`, checked as regular files and read with a 1 MiB bound; JSON is decoded strictly (duplicate keys and nesting deeper than 64 levels are errors).
- A `Statement` that is empty or null, and an undecodable `Principal`, `Action` or `Condition`, exit 2 instead of passing.
- `--fail-on` is trimmed and lowercased once, then validated.
- File names in text output are quoted with `%q`.
- CI checkout sets `persist-credentials: false`.
- `DECISIONS.md` records the 2026-11-14 cross-review status.

### Fixed

- A `.tf` file with several roles was scanned only for its first heredoc.
- Unreadable-as-heredoc `.tf` policies exited 0 with no findings.

### Known limits

- The build is Unix-only (`syscall.O_NOFOLLOW`).
- `jsonencode` HCL is not parsed. The OIDC `aud` claim and SAML trusts are not checked.
- The home account is unknown, so same-account ARNs are reported as cross-account.
