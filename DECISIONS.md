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

## 2026-11-13 phase 5 review

Finding: the README could be read as a claim that every Terraform trust policy is scanned. Resolution: the README repeats that jsonencode HCL is not parsed and that the home account is unknown. Checks were re-run on the committed tree. No second model was available.

## 2026-11-14 review fixes and cross-review status

Finding: the 2026-11-13 entries say no second model was available, and they were never edited. That is now out of date for this branch. Resolution: a cross-review did run on 2026-11-14 (`scripts/cross-review.sh`). The Cursor provider failed because the directory was not trusted, and the run fell back to openai (gpt-6.1-sol). That is a single-vendor review, not the intended Cursor one. Its output was saved as `.reviews/review-20261114-015256-openai.md` (the `.reviews/` directory is git-ignored, so it is not in the repository). The earlier entries are kept as written; this entry supersedes their "no second model" lines. The 17 findings from that review are fixed in the commits for plans/step-1.md to plans/step-3.md. `go.mod` stays at `go 1.26.11` (D10) because the local toolchain is go1.26.11 and resolves it. Cross-review was not re-run after the fixes; a re-review is still open.
