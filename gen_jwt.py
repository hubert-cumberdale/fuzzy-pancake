import jwt
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# Constants
ONE_HOUR = datetime.timedelta(hours=1)
SUBJECT = 'admin'
ROLES = ['all_access']

def generate_rsa_keys():
    # Generate RSA Keys
    private_key_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Serialize private key
    rsa_private_pem = private_key_rsa.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Serialize public key
    rsa_public_pem = private_key_rsa.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Save to files
    with open('rsa_private_key.pem', 'wb') as f:
        f.write(rsa_private_pem)
    with open('rsa_public_key.pem', 'wb') as f:
        f.write(rsa_public_pem)
    return rsa_private_pem

def generate_ecdsa_keys():
    # Define the EC curves
    curves = {
        'ES256': ec.SECP256R1(),
        'ES384': ec.SECP384R1(),
        'ES512': ec.SECP521R1()
    }
    ec_keys = {}
    # Generate and save ECDSA keys for each curve
    for label, curve in curves.items():
        private_key_ec = ec.generate_private_key(curve)
        ec_private_pem = private_key_ec.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        ec_public_pem = private_key_ec.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(f'{label.lower()}_private_key.pem', 'wb') as f:
            f.write(ec_private_pem)
        with open(f'{label.lower()}_public_key.pem', 'wb') as f:
            f.write(ec_public_pem)
        ec_keys[label] = ec_private_pem
    return ec_keys

def generate_jwt(key, algorithm):
    now = datetime.datetime.utcnow()
    payload = {
        'sub': SUBJECT,
        'iat': now,
        'nbf': now,  # Or set to a future time if needed
        'exp': now + datetime.timedelta(hours=1),  # Token expires in 1 hour
        'roles': ROLES
    }
    token = jwt.encode(payload, key, algorithm=algorithm)
    return token

def main():
    rsa_private_pem = generate_rsa_keys()
    ec_keys = generate_ecdsa_keys()

    # Print JWT for RSA and ECDSA
    print("RSA JWTs:")
    for alg in ['RS256', 'RS384', 'RS512']:
        token = generate_jwt(rsa_private_pem, alg)
        print(f"{alg}: {token}")

    print("\nECDSA JWTs:")
    for alg, key in ec_keys.items():
        token = generate_jwt(key, alg)
        print(f"{alg}: {token}")

if __name__ == '__main__':
    main()
