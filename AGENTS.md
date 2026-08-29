# Repository Workflow

## Default validation and delivery

Use this sequence for normal changes in this repository:

1. Run fast local gates first: formatting, diff checks, compilation-only Go tests, and focused tests that do not require unavailable host capabilities.
2. Work on an `agent/*` branch. Do not push unfinished work directly to `main`.
3. Push the branch and open a Draft PR targeting `main`. The PR event is the default way to run the complete GitHub Actions matrix in parallel (Go, mobile Go, Web, Flutter, and container checks).
4. Read only the failing job summaries and relevant log sections, fix those failures locally, and update the same branch/PR.
5. Merge into `main` only after all required PR checks pass. Verify the resulting `main` workflow, then delete the temporary local and remote branch.

Do not use `workflow_dispatch` merely to validate ordinary changes: this repository's manual workflow also enables release jobs. Push directly to `main` only when the user explicitly requests that exception, and still run the fastest relevant local gates first.

## Heavy validation goes to the cloud — do not grind locally

Local builds of the mobile Go library (and any other heavy dependency graph) are extremely slow and routinely time out. When an edit touches `mobile/` (or any package whose `go build` exceeds ~60s locally):

- Do NOT keep retrying the local build/vet with longer timeouts.
- Run only the cheapest syntax check locally (`gofmt -s -l` on the changed files, optional `go build` of just the changed package with a short timeout as a smoke test).
- Get real compilation/test signal from GitHub Actions: commit to an `agent/*` branch, push, and open a Draft PR against `main`. The `test-mobile-go` job compiles `mobile/` with cached dependencies and is far faster than local first-time downloads.
- Treat repeated local timeouts as the signal to go cloud-first, not as a reason to keep trying locally.
