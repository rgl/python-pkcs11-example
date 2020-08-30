#!/bin/bash
set -euxo pipefail

rm -rf tmp

mkdir -p tmp

pushd tmp

# set the environemnt variables used by the tests.
export TEST_PKCS11_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
export TEST_PKCS11_SO_PIN=4321
export TEST_PKCS11_USER_PIN=1234
export TEST_PKCS11_TOKEN_LABEL=test-token
export TEST_PKCS11_KEY_LABEL=test-rsa-2048

# configure softhsm to read the configuration from the current directory.
export SOFTHSM2_CONF=$PWD/softhsm2.conf
cat >softhsm2.conf <<EOF
directories.tokendir = $PWD/softhsm2-tokens
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = ERROR

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false
EOF
install -d -m 700 softhsm2-tokens

# initialize a test token.
# NB so-pin is the Security Office PIN (used to re-initialize the token).
softhsm2-util \
    --init-token \
    --free \
    --label $TEST_PKCS11_TOKEN_LABEL \
    --so-pin $TEST_PKCS11_SO_PIN \
    --pin $TEST_PKCS11_USER_PIN

# generate a key in the normal PKCS#1 format.
openssl genrsa \
    -out test-key.pem \
    2048 \
    2>/dev/null

# convert the key to the PKCS#8 format.
openssl pkcs8 \
    -topk8 \
    -inform pem \
    -in test-key.pem \
    -outform pem \
    -out test-key.pkcs8.pem \
    -nocrypt

# # show the key.
# openssl rsa \
#     -in test-key.pkcs8.pem \
#     -text \
#     -noout

# import it into the hsm (key must be in the PKCS#8 format).
softhsm2-util \
    --import test-key.pkcs8.pem \
    --token $TEST_PKCS11_TOKEN_LABEL \
    --label $TEST_PKCS11_KEY_LABEL \
    --id FFFF \
    --pin $TEST_PKCS11_USER_PIN

# show the objects.
pkcs11-tool --module $TEST_PKCS11_LIBRARY_PATH --list-slots --list-objects

popd

python3 main.py
