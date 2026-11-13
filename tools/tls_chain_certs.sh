#!/bin/bash
# From ekur tools/tls_chain_certs.sh at ba2c6c7; the certificates' names
# say ekur still, as the tests that read them expect.
#
# Writes src/testdata/tls_chain/: certificate chains, as DER, for
# test/security/tls_client_test.zig, which hands them to the transport's
# TLS client (deps/zig-tls) in a server's Certificate message (CONN-10,
# CONN-13), and for src/tls_cert.zig's tests. Each name is one certificate;
# the README there says which chain is which and what the client must do
# with it. Needs OpenSSL 3.4 or later (-not_before, -not_after):
#
#   OPENSSL=/opt/homebrew/bin/openssl tools/tls_chain_certs.sh
#
# Keys are made fresh and thrown away, so a rerun changes every file; the
# tests read only what the certificates say.
set -eu
OPENSSL=${OPENSSL:-openssl}
out=src/testdata/tls_chain
[ -d "$out" ] || { echo "run from the repository root" >&2; exit 1; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
serial=1

ca='basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign'
leaf='basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost'

# cert NAME ISSUER CN EXTENSIONS [rsa]: NAME.der, signed by ISSUER's key
# (or by its own when ISSUER is "self"), valid 2026 to 2126, with a P-256
# key, or an RSA 2048 one given "rsa". EXTENSIONS "none" is none at all,
# key identifiers included.
cert() {
  if [ "${5:-}" = rsa ]; then
    "$OPENSSL" genrsa -out "$W/$1.key" 2048 2> /dev/null
  else
    "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$W/$1.key"
  fi
  "$OPENSSL" req -new -key "$W/$1.key" -subj "/CN=$3" -out "$W/$1.csr"
  if [ "$4" = none ]; then
    printf 'subjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n' > "$W/$1.ext"
  else
    printf '%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' "$4" > "$W/$1.ext"
  fi
  if [ "$2" = self ]; then
    signer=(-key "$W/$1.key")
  else
    signer=(-CA "$W/$2.pem" -CAkey "$W/$2.key")
  fi
  "$OPENSSL" x509 -req -in "$W/$1.csr" "${signer[@]}" -set_serial "$serial" \
    -not_before 20260101000000Z -not_after 21260101000000Z -extfile "$W/$1.ext" -out "$W/$1.pem" 2> /dev/null
  "$OPENSSL" x509 -in "$W/$1.pem" -outform DER -out "$out/$1.der"
  serial=$((serial + 1))
}

cert root self "ekur test root" "$ca"

# The attack (CWE-296): a certificate the root signed for a name of the
# attacker's, not a CA, signs one for localhost.
cert attacker root "attacker.example" "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=DNS:attacker.example"
cert forged attacker "localhost" "$leaf"

# An issuer with no basicConstraints at all: not a CA either.
cert bare root "ekur bare issuer" "nsComment=no basicConstraints"
cert bare-leaf bare "localhost" "$leaf"

# An issuer with no extensions at all (OpenSSL still writes version 3):
# nothing in it reads as a CA.
cert plain root "ekur issuer without extensions" none
cert plain-leaf plain "localhost" "$leaf"

# A CA whose keyUsage leaves out keyCertSign: its key may not sign certificates.
cert no-sign root "ekur CA without keyCertSign" "basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature"
cert no-sign-leaf no-sign "localhost" "$leaf"

# pathLenConstraint 0: it may sign leaves, and no CA under it.
cert inter0 root "ekur intermediate pathlen 0" "basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign"
cert good inter0 "localhost" "$leaf"
cert deep inter0 "ekur intermediate under pathlen 0" "$ca"
cert deep-leaf deep "localhost" "$leaf"

# A self-issued certificate (the same name, a new key: a key rollover)
# under the pathlen 0 one does not count against it (RFC 5280 6.1.4 (l)).
cert rollover inter0 "ekur intermediate pathlen 0" "$ca"
cert rollover-leaf rollover "localhost" "$leaf"

# Two intermediates, the upper with no pathLenConstraint: taken.
cert open root "ekur intermediate open" "$ca"
cert open-sub open "ekur intermediate under open" "basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign"
cert open-leaf open-sub "localhost" "$leaf"

# An RSA leaf the root signed: what reaches std's RSA key and signature
# code, for test/security/tls_client_test.zig's crash tests and fuzzing (CONN-12).
cert rsa-leaf root "localhost" "$leaf" rsa

# The limits a certificate states (CONN-13; ekur t383).
host_only='basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth'

# nameConstraints: a CA held to example.com signs for localhost, directly,
# by a common name with no subjectAltName (std's host check falls back to
# it), and through an unconstrained CA under it.
cert nc-dns root "ekur CA for example.com" "$ca
nameConstraints=critical,permitted;DNS:example.com"
cert nc-dns-leaf nc-dns "localhost" "$leaf"
cert nc-cn-leaf nc-dns "localhost" "$host_only"
cert nc-mid nc-dns "ekur CA under the example.com one" "$ca"
cert nc-mid-leaf nc-mid "localhost" "$leaf"
# A leaf for www.example.com is in it; through a CA whose own
# subjectAltName (localhost) is not, it is refused all the same.
www='basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:www.example.com'
cert nc-www-leaf nc-dns "www.example.com" "$www"
cert nc-san-mid nc-dns "ekur CA named localhost" "$ca
subjectAltName=DNS:localhost"
cert nc-san-leaf nc-san-mid "www.example.com" "$www"
# One held to localhost signs for it: taken.
cert nc-ok root "ekur CA for localhost" "$ca
nameConstraints=critical,permitted;DNS:localhost"
cert nc-ok-leaf nc-ok "localhost" "$leaf"
# One that may sign for anything but localhost.
cert nc-excl root "ekur CA for all but localhost" "$ca
nameConstraints=critical,excluded;DNS:localhost"
cert nc-excl-leaf nc-excl "localhost" "$leaf"
# IP addresses held to 10/8; the leaf is for 127.0.0.1.
cert nc-ip root "ekur CA for net 10" "$ca
nameConstraints=critical,permitted;IP:10.0.0.0/255.0.0.0"
cert nc-ip-leaf nc-ip "127.0.0.1" "$host_only
subjectAltName=IP:127.0.0.1"
# Held to email addresses, a form ekur does not check.
cert nc-email root "ekur CA for mail at example.com" "$ca
nameConstraints=critical,permitted;email:.example.com"
cert nc-email-leaf nc-email "localhost" "$leaf"

# Extended key usage: a leaf for client logins, a CA for mail, and the
# ones that may serve TLS.
cert client-leaf root "localhost" "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:localhost"
cert any-leaf root "localhost" "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=anyExtendedKeyUsage
subjectAltName=DNS:localhost"
cert noeku-leaf root "localhost" "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=DNS:localhost"
cert smime root "ekur CA for mail" "$ca
extendedKeyUsage=emailProtection,clientAuth"
cert smime-leaf smime "localhost" "$leaf"
cert tls-ca root "ekur CA for TLS" "$ca
extendedKeyUsage=serverAuth,clientAuth"
cert tls-ca-leaf tls-ca "localhost" "$leaf"

# Critical extensions: one ekur does not know, a precertificate's poison,
# and policyConstraints on a CA; and an unknown one that is not critical.
cert crit-leaf root "localhost" "$leaf
1.2.3.4=critical,ASN1:NULL"
cert poison-leaf root "localhost" "$leaf
1.3.6.1.4.1.11129.2.4.3=critical,ASN1:NULL"
cert note-leaf root "localhost" "$leaf
1.2.3.4=ASN1:NULL"
cert policy root "ekur CA requiring a policy" "$ca
policyConstraints=critical,requireExplicitPolicy:0"
cert policy-leaf policy "localhost" "$leaf"

# Roots of their own, beside `root` in the tests' bundle: each one's
# limits hold for the chain under it.
cert nc-root self "ekur root for example.com" "$ca
nameConstraints=critical,permitted;DNS:example.com"
cert nc-root-leaf nc-root "localhost" "$leaf"
cert len-root self "ekur root pathlen 0" "basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign"
cert len-inter len-root "ekur CA under the pathlen 0 root" "$ca"
cert len-leaf len-inter "localhost" "$leaf"
cert eku-root self "ekur root for mail" "$ca
extendedKeyUsage=emailProtection"
cert eku-root-leaf eku-root "localhost" "$leaf"
cert crit-root self "ekur root with a critical extension" "$ca
1.2.3.4=critical,ASN1:NULL"
cert crit-root-leaf crit-root "localhost" "$leaf"
# A server's own self-signed certificate, which an app's `.ca` may pin:
# a root need not be a CA.
cert pinned self "ekur pinned" "$leaf"

echo "wrote $((serial - 1)) certificates to $out"
