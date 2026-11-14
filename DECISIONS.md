# Decisions

## 2026-11-13: Local repo, GitHub create not available

Context: `iam-trust-audit` did not exist on GitHub (`search` total 0, anonymous clone asked for a username). `gh` is not logged in.

Choice: scaffold with `new-project.sh` from agent-pairing-kit on this machine. Push and GitHub repo creation stay blocked until credentials exist. Work is on `improve/tldr-catchup-2026-11-13`, not on the scaffold commit's `main`.

Why: The tool can still be built and checked here. Inventing a remote would not create the repository.

## 2026-11-13 phase 1 review

Checklist: correctness, resources, untrusted input, errors, tests, security.

Finding: an unpinned GitHub Action would make CI depend on a moving tag. Resolution: pin `actions/checkout` to `11bd71901bbe5b1630ceea73d27597364c9af683` and `actions/setup-go` to `d35c59abb061a4a6fb18e82ac0862c26744d6ab5` (tag v5.5.0). No second model was available to run `scripts/cross-review.sh`. This pass is the review checklist, not a claim that another provider ran.
