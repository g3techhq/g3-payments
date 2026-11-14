#!/bin/sh
# Regenerates the synthetic App Store signing chain the JWS verifier tests use.
# None of this is Apple's: the root is a stand-in for Apple Root CA - G3, so the
# tests can sign payloads the way Apple does (x5c = leaf, intermediate, root)
# and check that the production verifier, trusting only Apple's real root,
# rejects them. The keys are throwaway test keys.
#
# Run from this directory: sh generate.sh
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/ext.cnf" <<'CNF'
[intermediate]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
# Apple's marker for the WWDR intermediate.
1.2.840.113635.100.6.2.1 = ASN1:NULL

[intermediate_unmarked]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
# Apple's marker for the App Store receipt-signing leaf.
1.2.840.113635.100.6.11.1 = ASN1:NULL

[leaf_unmarked]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF

days=36500

openssl ecparam -name secp384r1 -genkey -noout -out "$work/root.key"
openssl req -new -x509 -sha384 -key "$work/root.key" -days "$days" \
  -subj "/CN=Test Root CA - G3/O=Greenside Partee Tests" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$work/root.pem"

issue() { # name key-curve issuer-name extensions
  openssl ecparam -name "$2" -genkey -noout -out "$work/$1.key"
  openssl req -new -key "$work/$1.key" -subj "/CN=Test $1/O=Greenside Partee Tests" -out "$work/$1.csr"
  openssl x509 -req -sha384 -in "$work/$1.csr" -CA "$work/$3.pem" -CAkey "$work/$3.key" \
    -set_serial "0x$(openssl rand -hex 8)" -days "$days" \
    -extfile "$work/ext.cnf" -extensions "$4" -out "$work/$1.pem"
}

issue intermediate secp384r1 root intermediate
issue intermediate_unmarked secp384r1 root intermediate_unmarked
issue leaf prime256v1 intermediate leaf
issue leaf_unmarked prime256v1 intermediate leaf_unmarked
issue leaf_under_unmarked prime256v1 intermediate_unmarked leaf
issue other_leaf prime256v1 intermediate leaf

for cert in root intermediate intermediate_unmarked leaf leaf_unmarked leaf_under_unmarked other_leaf; do
  openssl x509 -in "$work/$cert.pem" -outform der -out "$cert.der"
done
for key in leaf leaf_unmarked leaf_under_unmarked other_leaf; do
  openssl pkcs8 -topk8 -nocrypt -in "$work/$key.key" -outform der -out "$key.key.der"
done
