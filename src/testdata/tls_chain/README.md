# Test certificate chains

From ekur (its src/runtime/testdata/tls_chain at ba2c6c7, karte t380 and
t383), so the names in the certificates say ekur. Certificates, as DER,
that test/security/tls_client_test.zig sends to the transport's TLS
client (deps/zig-tls) in a server's Certificate message (CONN-10,
CONN-13); src/tls_cert.zig's tests read each whole. All but
`rsa-leaf` are EC P-256, valid 2026-01-01 to 2126-01-01, made by
tools/tls_chain_certs.sh with OpenSSL 3.4 or later:

    OPENSSL=/opt/homebrew/bin/openssl tools/tls_chain_certs.sh

The tests trust six roots: `root`, which signed most chains, and
`nc-root`, `len-root`, `eku-root`, `crit-root` and `pinned`, each there
for its own limits. Each chain is sent server's certificate first; every
leaf is for `localhost` unless the row says otherwise.

| Chain | What it is | The client |
| --- | --- | --- |
| forged, attacker | `attacker` (CA:FALSE, digitalSignature) is for attacker.example, signed by the root; its key signed `forged` | refuses: CertificateIssuerNotCa |
| bare-leaf, bare | `bare` has no basicConstraints | refuses: CertificateIssuerNotCa |
| plain-leaf, plain | `plain` has no extensions at all | refuses: CertificateIssuerNotCa |
| no-sign-leaf, no-sign | `no-sign` is CA:TRUE, but its keyUsage is digitalSignature alone | refuses: CertificateIssuerKeyUsage |
| deep-leaf, deep, inter0 | `inter0` has pathlen 0, and signed `deep`, another CA | refuses: CertificatePathLenExceeded |
| good, inter0 | a leaf under the pathlen 0 intermediate | takes it |
| rollover-leaf, rollover, inter0 | `rollover` is self-issued (inter0's name, a new key), which pathlen does not count | takes it |
| open-leaf, open-sub, open | two intermediates, the upper with no pathlen | takes it |
| rsa-leaf | an RSA 2048 leaf the root signed | takes it |
| nc-dns-leaf, nc-dns | `nc-dns` is held by nameConstraints to example.com | refuses: CertificateNameConstraints |
| nc-cn-leaf, nc-dns | no subjectAltName, so its common name, localhost, is the name std's host check takes | refuses: CertificateNameConstraints |
| nc-mid-leaf, nc-mid, nc-dns | `nc-mid`, with no constraints, is under `nc-dns` | refuses: CertificateNameConstraints |
| nc-www-leaf, nc-dns | for www.example.com (host www.example.com) | takes it |
| nc-san-leaf, nc-san-mid, nc-dns | for www.example.com, through `nc-san-mid`, whose own subjectAltName is localhost | refuses: CertificateNameConstraints |
| nc-ok-leaf, nc-ok | `nc-ok` is held to localhost | takes it |
| nc-excl-leaf, nc-excl | `nc-excl` excludes localhost | refuses: CertificateNameConstraints |
| nc-ip-leaf, nc-ip | for IP 127.0.0.1 (host 127.0.0.1); `nc-ip` is held to 10.0.0.0/8 | refuses: CertificateNameConstraints |
| nc-email-leaf, nc-email | `nc-email` is held to email addresses, a form ekur does not check | refuses: CertificateNameConstraints (OpenSSL takes it) |
| client-leaf | extendedKeyUsage clientAuth alone | refuses: CertificateExtKeyUsage |
| any-leaf | extendedKeyUsage anyExtendedKeyUsage alone | refuses: CertificateExtKeyUsage |
| noeku-leaf | no extendedKeyUsage | takes it |
| smime-leaf, smime | `smime`'s extendedKeyUsage is emailProtection and clientAuth | refuses: CertificateExtKeyUsage |
| tls-ca-leaf, tls-ca | `tls-ca`'s extendedKeyUsage is serverAuth and clientAuth | takes it |
| crit-leaf | a critical extension, 1.2.3.4 | refuses: CertificateUnhandledCriticalExtension |
| poison-leaf | Certificate Transparency's poison, critical: a precertificate | refuses: CertificateUnhandledCriticalExtension |
| note-leaf | 1.2.3.4, not critical | takes it |
| policy-leaf, policy | `policy` has policyConstraints (requireExplicitPolicy 0), critical | refuses: CertificateUnhandledCriticalExtension (OpenSSL takes it) |
| nc-root-leaf | `nc-root`, a root, is held to example.com | refuses: CertificateNameConstraints |
| len-leaf, len-inter | `len-root`, a root with pathlen 0, signed `len-inter`, a CA | refuses: CertificatePathLenExceeded |
| eku-root-leaf | `eku-root`'s extendedKeyUsage is emailProtection | refuses: CertificateExtKeyUsage |
| crit-root-leaf | `crit-root` has a critical extension, 1.2.3.4 | refuses: CertificateUnhandledCriticalExtension |
| pinned | self-signed, CA:FALSE, the root it is in the bundle as | takes it |

`openssl verify -CAfile <its root>.pem -untrusted <the rest> -purpose
sslserver -verify_hostname <host> <leaf>` (`-verify_ip` for
127.0.0.1) agrees with each row but two: OpenSSL checks email
constraints and policies, which ekur refuses rather than pass over, and
for nc-cn-leaf it says hostname mismatch, since it does not fall back to
the common name as std does.
