# Repository Workflow

## Default validation and delivery

Use this sequence for normal changes in this repository:

1. Run fast local gates first: formatting, diff checks, compilation-only Go tests, and focused tests that do not require unavailable host capabilities.
2. Work on an `agent/*` branch. Do not push unfinished work directly to `main`.
3. Push the branch and open a Draft PR targeting `main`. The PR event is the default way to run the complete GitHub Actions matrix in parallel (Go, mobile Go, Web, Flutter, and container checks).
4. Read only the failing job summaries and relevant log sections, fix those failures locally, and update the same branch/PR.
5. Merge into `main` only after all required PR checks pass. Verify the resulting `main` workflow, then delete the temporary local and remote branch.

Do not use `workflow_dispatch` merely to validate ordinary changes: this repository's manual workflow also enables release jobs. Push directly to `main` only when the user explicitly requests that exception, and still run the fastest relevant local gates first.
