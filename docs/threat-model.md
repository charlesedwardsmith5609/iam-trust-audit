# Threat model

The tool reads files the operator names. It does not authenticate to AWS. A finding is a claim about the file, not about a live account.

## What it is for

A trust policy can let the wrong principal assume a role. The rules in REQUIREMENTS.md are the ones this tool checks.

## What it is not

- It does not prove a live role is safe. A file that is not the policy AWS stored will look fine.
- It does not parse `jsonencode` HCL. A `.tf` `assume_role_policy` that is not a JSON heredoc (`jsonencode`, a data source, a quoted string, or a heredoc with no terminator) is reported as a high `IAM-UNPARSED` finding, not skipped. A full HCL parser would be a new dependency, which this project does not take.
- It does not check the OIDC `aud` claim. A missing `aud` condition is not a finding.
- The OIDC `sub` check requires a positive operator (`StringEquals`, `StringLike`, `IpAddress`, each optionally with `ForAnyValue:`; the same set decides `sts:ExternalId`, `aws:SourceIp` and `aws:PrincipalOrgID`). When the statement names one Federated provider, the `sub` key must belong to that provider; otherwise any `<provider>:sub` key counts. `*` and `?` in a `sub` value are reported as a wildcard.
- It checks only `Allow` statements (no `Effect` counts as `Allow`). A `Deny` statement is skipped and is not used to offset an `Allow`.
- It audits OIDC and AWS-account trusts only. A SAML or other `Federated` provider is not checked.
- The build is Unix-only because files are opened with `O_NOFOLLOW` (`syscall.O_NOFOLLOW`).
- It cannot tell a same-account principal from a cross-account principal. Every AWS account ARN on `sts:AssumeRole` is reported as cross-account.

## Assets

The files can contain account ids and external ids. The report names the file, the statement index, the rule id, and a fix hint. It does not print the policy body.

## Failure

An unreadable file, a non-regular file (a FIFO or device), a symlink as the last path component, a file over 1 MiB, a JSON syntax error, a duplicate JSON key, nesting deeper than 64 levels, an empty or null `Statement`, or an undecodable `Principal`, `Action` or `Condition` exits 2. A symlinked parent directory is still followed. The tool does not skip a broken file and then exit 0.
