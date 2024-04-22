import jwt
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# Constants
ONE_HOUR = datetime.timedelta(hours=1)
SUBJECT = 'user123'
ROLES = ['admin', 'user']

# Generate RSA and EC Keys and save them to files
def generate_keys():
    # RSA Keys
    private_key_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_private_pem = private_key_rsa.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    rsa_public_pem = private_key_rsa.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('rsa_private_key.pem', 'wb') as f:
        f.write(rsa_private_pem)
    with open('rsa_public_key.pem', 'wb') as f:
        f.write(rsa_public_pem)

    # EC Keys
    private_key_ec = ec.generate_private_key(ec.SECP256R1())
    ec_private_pem = private_key_ec.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    ec_public_pem = private_key_ec.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('ec_private_key.pem', 'wb') as f:
        f.write(ec_private_pem)
    with open('ec_public_key.pem', 'wb') as f:
        f.write(ec_public_pem)

    return rsa_private_pem, rsa_public_pem, ec_private_pem, ec_public_pem

generate_keys()

# HMAC keys (not saved to files, shown for completeness)
hmac_keys = {
    'HS256': 'secret256',
    'HS384': 'secret384',
    'HS512': 'secret512'
}

# Payload for JWT
payload = {
    'sub': SUBJECT,
    'exp': datetime.datetime.utcnow() + ONE_HOUR,
    'roles': ROLES
}

# Function to generate JWT for a given algorithm
def generate_jwt(algorithm, private_key):
    return jwt.encode(payload, private_key, algorithm=algorithm)