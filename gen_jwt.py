import jwt
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# Constants
ONE_HOUR = datetime.timedelta(hours=1)
SUBJECT = 'user123'
ROLES = ['admin', 'user']

# Generate RSA and EC Keys
def generate_keys():
    # RSA
    private_key_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_private_pem = private_key_rsa.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.PKCS8,
                                                    encryption_algorithm=serialization.NoEncryption())
    rsa_public_pem = private_key_rsa.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # EC
    private_key_ec = ec.generate_private_key(ec.SECP256R1())
    ec_private_pem = private_key_ec.private_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PrivateFormat.PKCS8,
                                                  encryption_algorithm=serialization.NoEncryption())
    ec_public_pem = private_key_ec.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return rsa_private_pem, rsa_public_pem, ec_private_pem, ec_public_pem

rsa_private_pem, rsa_public_pem, ec_private_pem, ec_public_pem = generate_keys()

# HMAC keys
hmac_keys = {
    'HS256': 'secret256',
    'HS384': 'secret384',
    'HS512': 'secret512'
}

# Payload
payload = {
    'sub': SUBJECT,
    'exp': datetime.datetime.utcnow() + ONE_HOUR,
    'roles': ROLES
}

# JWT Generation
def generate_jwt(algorithm):
    if algorithm.startswith('HS'):  # HMAC Algorithms
        return jwt.encode(payload, hmac_keys[algorithm], algorithm=algorithm)
    elif algorithm.startswith('RS') or algorithm.startswith('PS'):  # RSA Algorithms
        return jwt.encode(payload, rsa_private_pem, algorithm=algorithm)
    elif algorithm.startswith('ES'):  # ECDSA Algorithms
        return jwt.encode(payload, ec_private_pem, algorithm=algorithm)

# Test all algorithms
algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512']
for alg in algorithms:
    token = generate_jwt(alg)
    print(f"JWT ({alg}): {token}")

