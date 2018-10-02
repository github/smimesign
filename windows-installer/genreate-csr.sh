#!/bin/bash
set -e

export KEY_PASSWORD=$(head -n100 /dev/urandom | shasum -a256 | awk '{print $1}')
echo "Key passphrase (save this): $KEY_PASSWORD"

openssl req -new -utf8 -out req.pem -newkey rsa:2048 -keyout key.pem -passout env:KEY_PASSWORD -config codesign.conf



