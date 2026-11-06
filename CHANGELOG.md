# Changelog

Until 1.0, minor versions may break the API; each entry says how.

## 0.1.0 (unreleased)

- The repository: build, test runner, and the empty `rest_core` module.
- `zig build test` runs zigvet and gnarl (0.7.0, named in
  `complexity.zon`): a zigvet finding, or a function newly over its
  complexity limit or worse than `complexity.baseline`, fails it.
- A security catalog, test/security/CATALOG.md: every known attack on an
  HTTP and REST client, each with its defence and the work that will
  prove it, checked against the tests by `zig build test`. SECURITY.md
  says how to report a vulnerability.
