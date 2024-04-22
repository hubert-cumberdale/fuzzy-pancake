import jwt
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# Constants
ONE_HOUR = datetime.timedelta(hours=1)
SUBJECT = 'user123'
ROLES = ['admin', 'user']

# Generate RSA and EC Keys for different curves and save them to files
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

    # Saving RSA keys to files
    with open('rsa_private_key.pem', 'wb') as f:
        f.write(rsa_private_pem)
    with open('rsa_public_key.pem', 'wb') as f:
        f.write(rsa_public_pem)

    # EC Keys for different curves
    curves = {
        'ES256': ec.SECP256R1(),
        'ES384': ec.SECP384R1(),
        'ES512': ec.SECP521R1()
    }
    ec_keys = {}
    for label, curve in curves.items():
        private_key_ec = ec.generate_private_key(curve)
        ec_private_pem = private_key_ec.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        ec_keys[label] = ec_private_pem
        with open(f'{label.lower()}_private_key.pem', 'wb') as f:
            f.write(ec_private_pem)

    return rsa_private_pem, rsa_public_pem, ec_keys

rsa_private_pem, rsa_public_pem, ec_keys = generate_keys()

# HMAC keys
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
def generate_jwt(algorithm, key):
    return jwt.encode(payload, key, algorithm=algorithm)

# Generate and print JWTs for all supported algorithms
def print_all_jwts():
    # Read RSA key from file
    with open('rsa_private_key.pem', 'rb') as f:
        rsa_private_key = f.read()

    # Algorithms and their corresponding keys
    algorithms = {
        'HS256': hmac_keys['HS256'],
        'HS384': hmac_keys['HS384'],
        'HS512': hmac_keys['HS512'],
        'RS256': rsa_private_key,
        'RS384': rsa_private_key,
        'RS512': rsa_private_key,
        'PS256': rsa_private_key,
        'PS384': rsa_private_key,
        'PS512': rsa_private_key,
        'ES256': ec_keys['ES256'],
        'ES384': ec_keys['ES384'],
        'ES512': ec_keys['ES512']
    }

    for alg, key in algorithms.items():
        token = generate_jwt(alg, key)
        print(f"JWT ({alg}): {token}")

print_all_jwts()
