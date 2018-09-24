set -e

KEY_FILE=key.pem
if [ -f $KEY_FILE ]; then
    read -p "Key passphrase: " -s KEY_PASSWORD
    KEY_OPTS="-key $KEY_FILE -passin env:KEY_PASSWORD"
else
    KEY_PASSWORD=$(head -n100 /dev/urandom | shasum -a256 | awk '{print $1}')
    echo "Key passphrase (save this): $KEY_PASSWORD"
    KEY_OPTS="-newkey rsa:2048 -keyout $KEY_FILE -passout env:KEY_PASSWORD"
fi
export KEY_PASSWORD

openssl req -new -utf8 -out req.pem $KEY_OPTS -config codesign.conf



