# iam-trust-audit

Scans IAM role trust policies and reports wildcard principals, missing `sts:ExternalId` on cross-account assume-role, missing or wildcard OIDC `sub` claims (including GitHub Actions), and cross-account trusts that have neither `aws:SourceIp` nor `aws:PrincipalOrgID`.

It reads JSON files and Terraform `assume_role_policy` heredocs. It also reads `aws iam get-role` output (`Role.AssumeRolePolicyDocument`, as an object or a string) and percent-encoded policy documents. It does not parse `jsonencode` HCL (a `.tf` `assume_role_policy` that is not a JSON heredoc is reported as `IAM-UNPARSED`) and it does not call AWS. See `REQUIREMENTS.md` and `docs/threat-model.md`.

```bash
go run ./cmd/iam-trust-audit --format text policy.json
go run ./cmd/iam-trust-audit --format json --fail-on high policy.json
bash scripts/check.sh
```

Exit 0 when no finding is at or above `--fail-on` (default `low`). Exit 1 when one is. Exit 2 when a file cannot be read or parsed. A symlink as the last path component, a file that is not a regular file (such as a FIFO or device), and a file over 1 MiB are refused; a symlinked parent directory is still followed. The report never prints the policy body.

Every AWS account ARN on `sts:AssumeRole` is treated as cross-account, because this tool does not know the home account.
