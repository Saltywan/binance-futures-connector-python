import hmac
import hashlib
from base64 import b64encode
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Signature import eddsa


def hmac_hashing(secret, payload):
    m = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256)
    return m.hexdigest()


def rsa_signature(private_key, payload, private_key_pass=None):
    private_key = RSA.import_key(private_key, passphrase=private_key_pass)
    h = SHA256.new(payload.encode("utf-8"))
    signature = pkcs1_15.new(private_key).sign(h)
    return b64encode(signature)

def ed25519_signature(private_key, payload):
    private_key = ECC.import_key(private_key)
    signature = eddsa.new(private_key, 'rfc8032').sign(payload.encode("utf-8"))
    return b64encode(signature)