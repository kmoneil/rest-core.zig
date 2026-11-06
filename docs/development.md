[Docs](README.md) › Development

# Development

## Build steps

```sh
zig build test                          # unit, property and fuzz-corpus tests, and zig fmt --check
zig build test --seed=0x1234            # the same, with other pseudo-random inputs
zig build test-unit                     # the tests alone, compiling nothing else
zig build test-release                  # the unit tests, the library built ReleaseSafe and ReleaseFast
zig build test -Dfuzz-runner --fuzz     # coverage-guided fuzzing, LLVM backend
zig build test -Dtest-filter=fuzz       # only the fuzz properties
zig build fmt                           # format the Zig
zig build docs                          # the API reference, into zig-out/docs
```

Every test build runs under `tools/test_runner.zig`: Zig 0.17's test
runner with `std.debug` waiting uncancelably, carried from gcp.zig, whose
docs/zig-std-workarounds.md says why.

## Where the code came from

Most of this library is gcp.zig's `src/core`, moved here. Each file that
came from there starts with a line naming the gcp.zig file and commit, so a
fix made in either can be carried to the other.

| File here | From gcp.zig | At |
| --- | --- | --- |
| tools/test_runner.zig | tools/test_runner.zig | eae944c |
