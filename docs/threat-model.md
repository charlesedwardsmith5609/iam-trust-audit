# Threat model

The tool reads files the operator names. It does not authenticate to AWS. A finding is a claim about the file, not about a live account.

## What it is for

A trust policy can let the wrong principal assume a role. The rules in REQUIREMENTS.md are the ones this tool checks.

## What it is not

- It does not prove a live role is safe. A file that is not the policy AWS stored will look fine.
- It does not parse `jsonencode` HCL. A policy written only that way is invisible to this tool. needs verification: a full HCL parser would be a new dependency, which this project does not take.
- It cannot tell a same-account principal from a cross-account principal. Every AWS account ARN on `sts:AssumeRole` is reported as cross-account.

## Assets

The files can contain account ids and external ids. The report names the file, the statement index, the rule id, and a fix hint. It does not print the policy body.

## Failure

An unreadable file, a symlink, a file over 1 MiB, or a JSON syntax error exits 2. The tool does not skip a broken file and then exit 0.
