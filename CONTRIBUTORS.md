# Contributors

thClaws is built primarily by [@mozeal](https://github.com/mozeal). The
contributors below have shipped real fixes and features — credit where
it's due.

## Community contributors

In rough order of first contribution.

### [@gobikom](https://github.com/gobikom)
- **PR [#139](https://github.com/thClaws/thClaws/pull/139)** —
  Cap spinner line width to terminal columns. Stopped the REPL
  spinner from wrapping on narrow terminals.

### [@modtanoii](https://github.com/modtanoii) (Chaiwat Chanavirat)
- **PR [#135](https://github.com/thClaws/thClaws/pull/135)** — Helm
  chart for self-hosted Kubernetes deployment. First-class k8s
  install path beyond docker-compose.
- **PR [#137](https://github.com/thClaws/thClaws/pull/137)** — Review
  follow-ups on the Helm chart.
- **PR [#140](https://github.com/thClaws/thClaws/pull/140)** — Bump
  the MiniMax default to MiniMax-M3 to match the current api.minimax.io
  flagship.

### [@sc28249782](https://github.com/sc28249782) (Somchai Pongkasem)
- **Issue [#141](https://github.com/thClaws/thClaws/issues/141)** —
  Reported, root-caused, AND tested a fix for the
  `split_shell_segments` UTF-8 panic. The fix proposal landed
  essentially as-is in v0.30.0. Exactly the kind of bug report that
  closes itself.

## How to be listed

1. **Open a PR** — even small ones (typo fix, documentation,
   regression test). Every merged PR earns a line.
2. **File a high-quality bug report** with a tested fix — like #141.
   We'll usually apply the fix and credit you in the next release.
3. **Contribute to the user manual** — translations, new chapters,
   diagrams.

Be courteous in discussions, follow the existing style of the file
you're editing, and keep PRs small + scoped. CI must be green
before merge.

If you've shipped a fix and aren't on this list, open an issue
titled "add me to CONTRIBUTORS" — we'll add you.
