//! Every example README.md and docs/ show, compiled and run by `zig build
//! test`. tools/doc_examples.zig keeps each document's copy of an example
//! identical to its file here.

test {
    _ = @import("http_transport.zig");
    _ = @import("cloud_hook.zig");
    _ = @import("testing_with_fakes.zig");
}
