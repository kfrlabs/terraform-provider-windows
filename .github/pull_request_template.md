## What

<!-- 1-2 lines: scope and intent. -->

## Why

<!-- Link an issue, an ADR, or paste the user-facing rationale. -->

## Checklist

- [ ] `go test -short ./...` passes locally
- [ ] `golangci-lint run` clean
- [ ] `make docs` ran (if a `Schema(...)` was touched or an example added)
- [ ] CHANGELOG entry under `## [Unreleased]` (Added / Changed / Fixed / Security)
- [ ] Acceptance tests `TF_ACC=1 go test ./...` ran against a Windows host (if applicable)
- [ ] Breaking change? Document migration in CHANGELOG and bump the planned next minor.

## Notes for reviewers

<!-- Trade-offs, alternatives considered, anything reviewers should not infer from the diff alone. -->
