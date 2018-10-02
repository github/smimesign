#!/bin/bash
set -e

# use sha1, since there is a max pw length
export KEY_PASSWORD=$(head -n100 /dev/urandom | shasum | awk '{print $1}')
echo "PFX passphrase (save this): $KEY_PASSWORD"

openssl pkcs7 -in chain.p7b -inform PEM -out result.pem -print_certs
trap "rm result.pem" EXIT

openssl pkcs12 -export -inkey key.pem -in result.pem -out codesign.pfx -passout env:KEY_PASSWORD

