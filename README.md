# iam-trust-audit

Reads IAM role trust policies from files and reports risky trust. It does not call AWS and does not change any account. A finding is a claim about the file, not about a live account.

## Run

```bash
go run ./cmd/iam-trust-audit --format text policy.json
go run ./cmd/iam-trust-audit --format json --fail-on high policy.json role.tf
bash scripts/check.sh
```

Arguments are files (no directory walking). Flags:

- `--format text|json` (default `text`). The value is case-sensitive; anything else exits 2.
- `--fail-on low|medium|high` (default `low`). The value is trimmed and lowercased, so `HIGH` works; anything else exits 2.

Both text and JSON list every finding; `--fail-on` only sets the exit code. JSON output is `{"fail_on": ..., "findings": [...]}`.

The build is Unix-only: `internal/parse` uses `syscall.O_NOFOLLOW`, and `GOOS=windows go build ./...` fails with `undefined: syscall.O_NOFOLLOW`.

## Exit codes

- 0: no finding at or above `--fail-on`.
- 1: at least one finding at or above `--fail-on`.
- 2: usage error (no files, unknown flag, bad `--format` or `--fail-on`), or an input file cannot be read or parsed. The run stops at the first bad file and prints no report.

## Input

- Raw trust policy JSON (a `Statement` array or a single `Statement` object).
- `aws iam get-role` output: `Role.AssumeRolePolicyDocument`, as an object or as a string. A bare `AssumeRolePolicyDocument` wrapper also works.
- Percent-encoded policy documents (text starting with `%7B`), at top level or inside an `AssumeRolePolicyDocument` string.
- Terraform `.tf` files: every `assume_role_policy = <<EOT` or `<<-EOT` JSON heredoc is audited. The `<<` must be on the same line as the `=`, and the terminator is the line that equals the heredoc name after trimming whitespace. Any other `assume_role_policy` form (`jsonencode`, a data source reference, a quoted string, a heredoc with no terminator) is reported as a high `IAM-UNPARSED` finding and is not skipped. Invalid JSON inside a heredoc exits 2.

## What it refuses (exit 2)

- A file that cannot be opened or read.
- A symlink as the last path component, and any non-regular file (FIFO, device). A symlinked parent directory is still followed.
- A file over 1 MiB (1048576 bytes).
- JSON syntax errors, duplicate object keys, and nesting deeper than 64 levels.
- An empty or null `Statement`, an empty statement object, or an undecodable `Principal`, `NotPrincipal`, `Action`, `NotAction` or `Condition`.

## Rules

Only `Allow` statements are checked (a statement with no `Effect` is treated as `Allow`; `Deny` is skipped).

| Id | Severity | Reported when |
|---|---|---|
| `IAM-PRINCIPAL-WILDCARD` | high | `Principal` is `*` or a value contains `*` or `?`, or an `Allow` statement uses `NotPrincipal`. |
| `IAM-EXTERNAL-ID-MISSING` | high | Cross-account `sts:AssumeRole` with no usable `sts:ExternalId` condition. |
| `IAM-VENDOR-NETWORK-MISSING` | medium | Cross-account `sts:AssumeRole` with neither a usable `aws:SourceIp` nor a usable `aws:PrincipalOrgID` condition. |
| `IAM-OIDC-SUB-MISSING` | high | OIDC statement with no usable `sub` condition. |
| `IAM-OIDC-SUB-WILDCARD` | high | OIDC statement whose `sub` value is empty or contains `*` or `?`. |
| `IAM-UNPARSED` | high | A `.tf` `assume_role_policy` that is not a JSON heredoc (see Input). |

Definitions:

- Cross-account: the action matches `sts:AssumeRole` (case-insensitive; `*` and `?` in the pattern are honored; `NotAction` is honored) and an `AWS` principal is an ARN containing `:iam::` or a bare 12-digit account id (string or number). The tool does not know the home account, so a same-account ARN is also reported as cross-account. OIDC statements are not treated as cross-account.
- OIDC: the action is exactly `sts:AssumeRoleWithWebIdentity`, or a `Federated` principal contains `oidc-provider/` or `token.actions.githubusercontent.com`. SAML and other federated providers are not audited. The `aud` claim is not checked.
- Positive condition operator: `StringEquals`, `StringLike` or `IpAddress`, optionally prefixed `ForAnyValue:`, compared case-insensitively. Negations, `ForAllValues:`, `...IfExists` and `Null` do not count. Condition keys match case-insensitively, with an optional provider prefix.
- Usable: at least one positive condition on the key, with every value non-empty and without `*` or `?`. For `aws:SourceIp`, a `/0` range (`0.0.0.0/0`, `::/0`) is also not usable. For `sub`, when the statement names exactly one `Federated` provider the key must be `<provider host>:sub`; otherwise any `<provider>:sub` key counts.

Findings print the severity, rule id, file name (quoted, with the Terraform resource in parentheses for `.tf`), statement index, and a fix hint. The report never prints the policy body. For `IAM-UNPARSED` the statement index is 0 and the fix hint names the line.

## Checks and review scripts

`bash scripts/check.sh` runs the misbehavior and assertion heuristics, then gofmt, go vet, govulncheck and `go test -race -count=1`, and prints `CHECK PASSED` or `CHECK FAILED`. CI runs the same script.

`scripts/plan-review.sh` and `scripts/cross-review.sh` (PowerShell: `scripts/cross-review.ps1`) send a plan or a diff to a different AI provider for review. Before anything is sent, the request is scanned with gitleaks; if gitleaks is missing, finds a match, or fails, nothing is sent and the script exits non-zero (fails closed). `cross-review.sh` also never sends files whose names match its secret-file deny list (such as `.env*` and `*.pem`). Saved reviews go to `.reviews/`, which is git-ignored.

More: `REQUIREMENTS.md`, `docs/threat-model.md`, `DECISIONS.md`, `CHANGELOG.md`.
