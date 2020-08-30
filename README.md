[![Build status](https://github.com/rgl/python-pkcs11-example/workflows/Build/badge.svg)](https://github.com/rgl/python-pkcs11-example/actions?query=workflow%3ABuild)

# About

This is an example that encrypt/decrypts a secret with a PKCS#11 HSM using
the [danni/python-pkcs11](https://github.com/danni/python-pkcs11) library.

# Usage

Initialize the device as described in https://github.com/rgl/go-pkcs11-rsa-oaep.

Execute the following commands to encrypt/decrypt an example plaintext:

```bash
# install dependencies.
python3 -m pip install -r requirements.txt
# NB you can also install python-pkcs11 in a way that you can view/edit/hack the code:
#python3 -m pip install -e python-pkcs11==0.7.0

# execute the example.
export TEST_PKCS11_LIBRARY_PATH='/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so'
export TEST_PKCS11_USER_PIN='648219'
export TEST_PKCS11_TOKEN_LABEL='test-token (UserPIN)'
export TEST_PKCS11_KEY_LABEL='test-rsa-2048'
python3 main.py
```
