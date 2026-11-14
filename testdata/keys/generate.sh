#!/bin/sh
# Regenerates the throwaway keys the token-signing tests use. None of them is
# a real App Store or Google key.
#
# Run from this directory: sh generate.sh
set -eu
cd "$(dirname "$0")"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.key.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key.pem
