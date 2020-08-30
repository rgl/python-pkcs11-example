#!/usr/bin/python3

import os
import binascii
import textwrap
import pkcs11
import pkcs11.util.rsa
import cryptography
import cryptography.hazmat.backends
import cryptography.hazmat.primitives
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric
import cryptography.hazmat.primitives.asymmetric.padding

lib = pkcs11.lib(os.environ['TEST_PKCS11_LIBRARY_PATH'])
token_label = os.environ['TEST_PKCS11_TOKEN_LABEL']  # pkcs11-tool --module opensc-pkcs11.so --list-slots
key_label = os.environ['TEST_PKCS11_KEY_LABEL']      # pkcs11-tool --module opensc-pkcs11.so --list-slots --list-objects
user_pin = os.environ['TEST_PKCS11_USER_PIN']

# list supported mechanisms.
for slot in lib.get_slots():
    token = slot.get_token()
    if not token.flags&pkcs11.TokenFlag.TOKEN_INITIALIZED:
        continue
    print(f'token-label: {token.label}')
    for m in slot.get_mechanisms():
        info = slot.get_mechanism_info(m)
        print(f'mechanism: {m.name}')
        print(textwrap.indent(str(info), len('mechanism: ')*2*' '))

# get the token.
# NB lib.get_token(token_label=token_label) cannot be used due to
#    https://github.com/danni/python-pkcs11/issues/89
def get_token(lib, token_label):
    for slot in lib.get_slots():
        token = slot.get_token()
        if not token.flags&pkcs11.TokenFlag.TOKEN_INITIALIZED:
            continue
        stripped_token_label = token.label.rstrip('\0').rstrip()
        if stripped_token_label == token_label:
            return token
token = get_token(lib, token_label)

if not token:
    raise Exception(f'could not find token `{token_label}`')

# SmartCard-HSM and Nitrokey HSM are somewhat limited. Only key generation and
# private key operations (sign and decrypt) are supported. Public key operations
# should be done by extracting the public key and working on the local machine.
# see https://github.com/danni/python-pkcs11/blob/3345329b45f9bdc1d5be1f04d651bef4d6115baf/docs/opensc.rst#using-with-smartcard-hsm-nitrokey-hsm
# NB the device does not support OAEP (aka pkcs11.Mechanism.RSA_PKCS_OAEP, aka CKM_RSA_PKCS_OAEP).
#    see pkcs11-tool --list-mechanism
with token.open(user_pin=user_pin) as session:
    pub = session.get_key(label=key_label, key_type=pkcs11.KeyType.RSA, object_class=pkcs11.ObjectClass.PUBLIC_KEY)
    pri = session.get_key(label=key_label, key_type=pkcs11.KeyType.RSA, object_class=pkcs11.ObjectClass.PRIVATE_KEY)

    # do the encryption in the local machine because the device is not
    # capable of performing it.
    # NB if the device was able to encrypt we would simple do a
    #    pub.encrypt(plaintext).
    # NB it doesn't support encrypt because the mechanism flags, as displayed
    #    by pkcs11-tool --module opensc-pkcs11.so --list-mechanism, do not
    #    report it:
    #       RSA-X-509, keySize={1024,4096}, hw, decrypt, sign, verify
    #       RSA-PKCS, keySize={1024,4096}, hw, decrypt, sign, verify
    plaintext = 'abracadabra'.encode('utf-8')
    cryptography_backend = cryptography.hazmat.backends.default_backend()
    public_key_der = pkcs11.util.rsa.encode_rsa_public_key(pub)
    public_key = cryptography.hazmat.primitives.serialization.load_der_public_key(public_key_der, cryptography_backend)
    # NB be aware that PKCS1v15 is not recommended anymore, but our device
    #    does not support OAEP.
    # NB the device does not support pkcs11.Mechanism.RSA_PKCS_OAEP (aka CKM_RSA_PKCS_OAEP).
    # NB so we either use PKCS#1 v1.5 or we do the OAEP ourselfs and use raw
    #    X.509 without padding (pkcs11.Mechanism.RSA_X_509) like its being
    #    done at https://github.com/rgl/go-pkcs11-rsa-oaep.
    # NB the cryptography library does not have a raw oeap function available,
    #    so we have to either implement it ourselfs, or stick with PKCS1v15.
    #    it also does not have a raw encryption RSA primitive availble.
    #    see https://github.com/pyca/cryptography/issues/5425
    ciphertext = public_key.encrypt(
        plaintext,
        cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15())
    # with OAEP this would have been:
    # ciphertext = public_key.encrypt(
    #     plaintext,
    #     cryptography.hazmat.primitives.asymmetric.padding.OAEP(
    #         mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=cryptography.hazmat.primitives.hashes.SHA256()),
    #         algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
    #         label=None))
    print(f"cryptography_backend: {cryptography_backend}")
    print(f"plaintext: {plaintext}")
    print(f"ciphertext: {binascii.hexlify(ciphertext)}")

    # decrypt.
    # NB the device does not support pkcs11.Mechanism.RSA_PKCS_OAEP (aka CKM_RSA_PKCS_OAEP).
    # NB so we either use PKCS#1 v1.5 or we do the OAEP ourselfs and use raw X.509 without padding (pkcs11.Mechanism.RSA_X_509).
    actual_plaintext = pri.decrypt(ciphertext, mechanism=pkcs11.Mechanism.RSA_PKCS)
    print(f"plaintext: {actual_plaintext}")
