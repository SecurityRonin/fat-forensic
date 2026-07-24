# 9. Library publishing via release-plz, with a committed `Cargo.lock`

Date: 2026-07-24
Status: Accepted

## Context

The fleet release standard (`ronin-issen/CLAUDE.md`, "Library crate publishing
— release-plz") binds every repo that publishes library crates to **release-plz**
(PR-based, conventional-commit-driven) rather than hand-cut version bumps or the
tag-driven `release.yml` `crate` job (which is for binaries). Two lived gotchas
must be defused: (a) release-plz's default single-crate tag `v{{ version }}`
collides with the `v[0-9]*` binary-release trigger, and (b) a library repo whose
CI runs `cargo vet --locked` but does not commit its lock fresh-resolves every
dep on every run, so pinned vet exemptions go stale ("freshness treadmill").

## Decision

Adopt release-plz for both published crates (git `e1f4125` "adopt release-plz for
library publishing"). `release-plz.toml` sets `git_tag_name = "{{ package }}-v{{
version }}"` so tags read `fat-core-v0.1.3` — a `<name>-v…` tag has a letter, not
a digit, after the first `v`, so it never matches a `v[0-9]*` binary trigger; and
`release_commits = "^(feat|fix|perf|refactor|doc|revert)"` so chore/ci/test/style
commits never cut a release. The reader and analyzer version **independently**
(`dependencies_update = false`); library tags get a CHANGELOG entry, not a GitHub
Release (`git_release_enable = false`). `Cargo.lock` is **committed** (git
`ed6d077` "commit Cargo.lock to stabilize cargo-vet (end freshness treadmill)"),
alongside `cargo-vet` in the supply-chain gate (git `0caf841`).

## Consequences

- Merging the release PR is the single reviewed checkpoint before an
  irreversible crates.io publish; the changelog is generated, not hand-written.
- The `<name>-v…` tag scheme and the (absent-here) `v[0-9]*` binary trigger do
  not collide — the two controls the fleet requires are both in place.
- CI honors the committed lock, so vet exemptions stay valid until the lock is
  deliberately bumped (via Renovate `lockFileMaintenance`), not on every push.
- `fuzz/` is not a workspace member and is `publish = false`, so release-plz
  never sees it.
