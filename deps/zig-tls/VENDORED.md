# std's TLS and HTTP clients, vendored with patches

Two of std's files from the Zig that builds rest-core (0.17.1 today), each
with `std` imported as a package (t78, after ekur's copy, its t380, t382
and t383):

`Client.zig` is `std/crypto/tls/Client.zig` with three patches:

- **Each signer in the chain must be a CA** (CONN-10). After std checks
  that a certificate in the server's chain signed the one before it,
  `tls_chain.Path.issued` (src/tls_chain.zig, a module the copy imports by
  name) checks that it was allowed to: version 3, basicConstraints cA,
  keyCertSign if it has keyUsage, and its pathLenConstraint. Zig 0.17's
  client checks signatures and names alone (Codeberg ziglang/zig#35877 and
  #37353; the fix, PR #37354, is not merged), so anyone with a certificate
  a trusted root signed for a domain of their own could sign one for any
  host.
- **Each certificate held to the limits it states** (CONN-13).
  `Path.leaf` on the server's certificate and `Path.anchored` in place of
  std's look in the root bundle, with `Path.issued`: no critical extension
  the client does not process, serverAuth in any extended key usage, and
  the nameConstraints of each CA and of the root over every name below
  them. std reads no extension but the subjectAltName.
- **A server's bytes cannot crash it** (CONN-11, CONN-12). std's
  certificate parser trusts every DER length, and the client runs it on
  each certificate a server sends before anything is trusted, so four
  bytes that claim 64 KB panic a safe build. The copy calls
  `tls_chain.parse` (src/tls_cert.zig) in its place, which checks that
  nothing std will read, then or later (the subjectAltName, an RSA key),
  runs past its bytes before std parses it. And it refuses an RSA
  signature whose length is not the key's before std copies it into a
  buffer of the key's length, which a fast build would overflow (PR
  ziglang/zig#36695, open).

`HttpClient.zig` is `std/http/Client.zig` with `Client.zig` for its TLS
client. std.http.Client builds its TLS client itself, in a private
function, so carrying it is the only way the transport gets the patched
one. One more line differs, three times: `std.http.BodyWriter` points
back at the request that made it to tell it the body is done, and its
field is typed for std's Request, which this copy's is not. So the copy
leaves it null, and the transport clears `payload_pending` after `end`,
as BodyWriter would have (src/transport.zig, `bodyEnd`). A caller of
`HttpClient` that sends a body itself should do the same: the flag
matters only to a request freed with its response's body unread, which
std drains to keep the connection, and closes instead while the flag is
set.

`tools/zig_tls.zig` makes both: `zig build zig-tls` writes them from the
installed Zig, and `zig build test` fails when a copy is not exactly that
file plus the patches, so a Zig upgrade (or an edit by hand) is caught.
Do not edit them here. When a Zig release changes a line a patch looks
for, the tool names the patch: see whether std does that work itself now
(test/security/std_tls_test.zig holds std's own client to the bugs of
CONN-11 and CONN-12, test/tls/tls_test.zig's openssl tests and
test/security/tls_client_test.zig show what the copy must still do), and
drop that patch. With all of the TLS patches gone, drop this directory,
the `zig_tls`, `http_client` and `tls_chain` modules in build.zig, the
tool and the check, and point src/transport.zig back at `std.http.Client`.

Zig's MIT license is `LICENSE`.
