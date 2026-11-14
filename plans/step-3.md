# Step 3: LOW findings (review findings 14-17)

Covers: 14, 15, 16, 17. Decisions: D10, D12, D13. Depends on steps 1 and 2.

Assumptions:
- Finding 16: support `aws iam get-role` output (`Role.AssumeRolePolicyDocument`) and a URL-encoded document string (percent-decoding with `net/url.QueryUnescape`; `+` is not treated as a space for a policy, so `url.PathUnescape` is used). Supporting is smaller than documenting and is the safer reading (nothing silently unparsed).
- Finding 17: D10 says keep `go 1.26.11`. Verification of the local toolchain happens at implementation time with `go version`; only if the toolchain cannot be resolved does the change become `go 1.26` plus `toolchain go1.26.11`. This is a conditional change, so go.mod is in the file list.
- Finding 17 "DECISIONS.md says no cross-review ran" is handled by appending a dated entry. Existing text is not edited. The entry states what actually ran (cross-review.sh runs only if it is run; do not claim it ran unless it did).
- Finding 11's README symlink wording (last component only) is in step 2's behavior but the README text change is done here.

## Types

- `report.Text` prints `%q` for the file name: `fmt.Fprintf(w, "%s %s %q statement %d\n  fix: %s\n", ...)`. JSON already escapes.
- `main`: `level := strings.ToLower(strings.TrimSpace(*failOn))`, then `switch level { case "low","medium","high": default: exit 2 }`. `report.Rank` keeps its fail-closed default for unknown findings but no longer drives validation. `report.JSON` receives the normalized level.
- `parse.ParseJSON` accepts a top-level `{"Role":{"AssumeRolePolicyDocument":...}}`, a string-encoded document, and a percent-encoded string (detected by the prefix `%7B`, case-insensitive). Errors name the cause once; the path is wrapped only in `ReadFile` so it no longer repeats (`read path: path: ...`).
- CI: `actions/checkout` step gains `with: persist-credentials: false`. SHA pins are unchanged.

## Ownership

No shared state. `main` is single-goroutine.

## Tests (natural language, written failing first)

1. A file name containing a newline and an ANSI escape is printed quoted in text output, with no raw newline in the finding line (finding 14).
2. `--fail-on Medium`, `MEDIUM` and ` high` are accepted and behave as lowercase. `--fail-on urgent` and `--fail-on ""` exit 2 (exact). `--fail-on HIGH` is accepted (it was rejected before) (finding 15).
3. `aws iam get-role` JSON with `Role.AssumeRolePolicyDocument` as an object, as a JSON string, and as a percent-encoded string each parse and produce the same finding as the bare policy (finding 16).
4. A percent-encoded string that decodes to invalid JSON exits 2 and the stderr message contains the path exactly once.
5. A fixture check that parses `ci.yml`-independent facts is not possible with the standard library; instead a test reads `.github/workflows/ci.yml` and fails if the checkout step lacks `persist-credentials: false` (finding 17).
6. A test reads `go.mod` and fails if the `go` directive is not `1.26.11` or the pair `go 1.26` plus `toolchain go1.26.11` (D10).
7. A test reads `DECISIONS.md` and fails if it lacks a `2026-11-14` entry (finding 17).

## Files

- internal/report/report.go
- internal/report/report_test.go
- cmd/iam-trust-audit/main.go
- cmd/iam-trust-audit/main_test.go
- internal/parse/parse.go
- internal/parse/parse_test.go
- internal/parse/testdata/get-role.json
- internal/parse/testdata/get-role-string.json
- internal/parse/testdata/url-encoded.json
- .github/workflows/ci.yml
- go.mod
- DECISIONS.md
- README.md
