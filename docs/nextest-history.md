# Nextest history

Keel began with a fork of [nextest](https://github.com/nextest-rs/nextest).
The original fork is preserved at `nextest/` as an unsquashed subtree merge.
Its original commit objects and their ancestry are reachable from this
repository; they have not been rewritten or reconstructed.

- Upstream nextest base: `8f2d970b36d8be5b7aafbf201c07f0f87506b8e3`.
- Original Keel fork tip: `42c8559c6727f24bbaae34f3ada455b7865704fe`.
- The twelve commits between those revisions implement the initial Keel
  planning, gated scheduling, reporting and concurrent build/test work.
- The parent directory holds the separately developed Keel framework; the
  imported nextest workspace refers to its `crates/keel` and `crates/keel-decl`
  by relative path.

For the fork history as originally recorded, run:

```sh
git log --oneline 8f2d970b36d8be5b7aafbf201c07f0f87506b8e3..42c8559c6727f24bbaae34f3ada455b7865704fe
git log --follow -- nextest/nextest-runner/src/keel/gate.rs
```

The imported tree has its own upstream license files at
`nextest/LICENSE-MIT` and `nextest/LICENSE-APACHE`. Preserving its history
does not imply that the historical fork has passed current CI or that the
standalone framework and fork have been validated together.
