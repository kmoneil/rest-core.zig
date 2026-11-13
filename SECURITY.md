# Security

rest-core sits under libraries that hold credentials for somebody's cloud
account: it carries their bearer tokens, signs with their private keys, and
reads whatever a server sends back. Two things follow from that: no
credential may leak, and nothing a server or a network peer sends may crash
the client or pass a partial response off as a whole one.

## Reporting a vulnerability

Email **kevin@oneil.xyz**, or use GitHub's
[private vulnerability reporting](https://github.com/kmoneil/rest-core.zig/security/advisories/new).
Please do not open a public issue for a vulnerability.

You will get an acknowledgement within 3 working days. Fixed issues are
disclosed publicly within **90 days** of the report, sooner if a fix ships
earlier, later only by agreement with the reporter.

Include the version, the call, and if you can, the response that triggers
it.

## Supported versions

Pre-1.0. Until the v1.0 tag, only the latest release receives fixes.

## Threat model

**Assumed hostile: everything a server sends.** Production is reached over
TLS, but an emulator speaks plain HTTP, and a proxy or a compromised peer
can say anything. A response is parsed, never trusted, and bounded in size
and time.

**Trusted: the program using it.** Endpoints, credentials and limits come
from the program, not from the requests it handles. A program that sends a
request to a URL its own users give it needs a guard against server-side
request forgery of its own.

[test/security/CATALOG.md](test/security/CATALOG.md) lists every known
attack on an HTTP and REST client, with the test that proves the defence,
the work that will add it, or the reason it does not apply.

## TLS

Zig 0.17.1's TLS client, which `std.http.Client` builds, takes a
certificate signed by one that is not a CA (Codeberg ziglang/zig#35877;
the fix, PR #37354, is not merged), reads no certificate extension but
the subjectAltName, parses each certificate a server sends with a DER
reader that trusts every length, and copies an RSA signature into a
buffer the size of the key without checking its length (PR
ziglang/zig#36695, open). So a man in the middle with any certificate a
trusted root signed could pass for any host and be sent the bearer
token, and any server could crash the client, or in ReleaseFast make it
read and write out of bounds.

rest-core's transport does not use std's client as it is. It carries
std's TLS and HTTP clients in deps/zig-tls, patched after ekur's: each signer in a
chain is held to being a CA (CONN-10), each certificate is held to the
limits it and the CAs above it state (extended key usage,
nameConstraints, critical extensions: CONN-13), each certificate a
server sends is checked before std parses it (CONN-11), and an RSA
signature is held to its key's length (CONN-12). `zig build test` fails
when the copy is not exactly std's file plus those patches, so a Zig
upgrade cannot leave an old copy behind; deps/zig-tls/VENDORED.md says
when a patch can go.

## Known gaps

The TLS client checks no certificate's revocation (neither OCSP nor
CRLs), as std's does not. The catalog lists every other gap, each with
its card: CONN-08, a time limit that std's connect can outrun when an
`Io`'s async capacity is spent, is one.
