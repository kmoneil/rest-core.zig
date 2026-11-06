# Contributing

Bug reports, ideas and fixes are welcome as
[GitHub issues](https://github.com/kmoneil/rest-core.zig/issues) and pull
requests. For anything larger than a small fix, open an issue first so the
approach can be agreed on. A vulnerability goes as [SECURITY.md](SECURITY.md)
says, not in a public issue.

## Setup

You need Zig 0.17.1. `zig build test` also runs two programs that must be
on the PATH: [zigvet](https://github.com/kmoneil/zigvet), which reports
code the compiler accepts that is almost certainly wrong, and
[gnarl](https://github.com/kmoneil/gnarl), which holds each function to
its complexity limits (`brew install kmoneil/tap/zigvet kmoneil/tap/gnarl`).
gnarl must be the release `complexity.zon` names in `.gnarl`: two releases
can count the same function differently.

```
zig build test          # unit, property and fuzz-corpus tests, formatting, zigvet, gnarl
zig build test-release  # the unit tests with the library built ReleaseSafe and ReleaseFast
zig build fmt           # format the Zig
```

[docs/development.md](docs/development.md) lists every build step.

## Before a commit

- `zig build test test-release` passes, and prints nothing from zigvet or
  gnarl.
- `gnarl --diff HEAD` shows no function newly over its limit. A new
  function over a critical limit is refactored, not added to
  `complexity.baseline`.
- A file ported from gcp.zig keeps its first line, naming the gcp.zig file
  and commit it came from; `zig build provenance` lists what gcp.zig has
  changed in it since.
- A defence against a known attack has a row in
  [test/security/CATALOG.md](test/security/CATALOG.md) and a test named
  `security: ...` under test/security. Report a vulnerability as
  [SECURITY.md](SECURITY.md) says, not in a public issue.
