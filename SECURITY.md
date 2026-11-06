# Security

rest-core sits under libraries that hold credentials for somebody's cloud
account: it carries their bearer tokens, signs with their private keys, and
reads whatever a server sends back. Two things follow from that: no
credential may leak, and nothing a server or a network peer sends may crash
the client or pass a partial response off as a whole one.

## Reporting a vulnerability

Email **kevin@oneil.xyz**. Please do not open a public issue for a
vulnerability.

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
