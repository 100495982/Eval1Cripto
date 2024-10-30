import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from JSONManager import JSONManager
from SessionManager import UserSession


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class UserAuthenticator:

    @staticmethod
    def register():
        user_data = JSONManager.load_user_data()
        username = input("Enter a username: ")
        if username in user_data:
            print("Username already exists.")
            return False

        password = input("Enter a password: ")
        hashed_password = hash_password(password)

        # Generate a persistent ECDH key pair for the user
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()

        # Encrypt and store the private key
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        ).decode('utf-8')

        # Serialize the public key in PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Store user data and save public key to public_keys.json
        user_data[username] = {
            "password": hashed_password,
            "private_key": private_key_pem
        }
        JSONManager.save_user_data(user_data)
        JSONManager.save_public_key(username,
                                    public_key_pem)  # Ensures public key is saved

        print(f"User {username} registered successfully. Please log in.")
        return True

    @staticmethod
    def login():
        user_data = JSONManager.load_user_data()
        username = input("Username: ")
        if username not in user_data:
            print("Username does not exist.")
            return None

        password = input("Password: ")
        hashed_password = hash_password(password)

        if user_data[username]["password"] == hashed_password:
            print("Login successful.")
            return UserSession(username, password)
        else:
            print("Incorrect password.")
            return None