# Decisions

## 2026-11-13: Local repo, GitHub create not available

Context: `iam-trust-audit` did not exist on GitHub (`search` total 0, anonymous clone asked for a username). `gh` is not logged in.

Choice: scaffold with `new-project.sh` from agent-pairing-kit on this machine. Push and GitHub repo creation stay blocked until credentials exist. Work is on `improve/tldr-catchup-2026-11-13`, not on the scaffold commit's `main`.

Why: The tool can still be built and checked here. Inventing a remote would not create the repository.

## 2026-11-13 phase 1 review

Checklist: correctness, resources, untrusted input, errors, tests, security.

Finding: an unpinned GitHub Action would make CI depend on a moving tag. Resolution: pin `actions/checkout` to `11bd71901bbe5b1630ceea73d27597364c9af683` and `actions/setup-go` to `d35c59abb061a4a6fb18e82ac0862c26744d6ab5` (tag v5.5.0). No second model was available to run `scripts/cross-review.sh`. This pass is the review checklist, not a claim that another provider ran.

## 2026-11-13 phase 2 review

Finding: a large or linked file could be read by mistake, including a secret outside the tree. Resolution: ReadFile uses Lstat, rejects symlinks, and rejects files over 1 MiB. JSON syntax errors return an error instead of an empty policy. No second model was available.

## 2026-11-13 phase 3 review

Finding: the tool cannot know the home account, so a same-account ARN looks like a vendor. Resolution: every AWS account ARN on sts:AssumeRole is treated as cross-account. OIDC statements are not also flagged as vendors. The scaffold Go 1.22.2 stdlib failed govulncheck, so go.mod is 1.26.11. No second model was available.

## 2026-11-13 phase 4 review

Finding: a JSON report that echoed the policy could print an external id or a secret stored in a condition. Resolution: text and JSON include id, severity, file, statement index, and the fix hint only. No second model was available.
