import hashlib
import os

def hash_password(password: str) -> tuple[str, str]:
    # Generate a random salt
    salt = os.urandom(32)

    # Combine the password and salt
    salted_password = password.encode('utf-8') + salt

    # Hash the salted password using SHA-256
    hashed_password = hashlib.sha256(salted_password).hexdigest()

    # Display the salt and hashed password
    print(f"Salt: {salt.hex()}")
    print(f"Hashed Password: {hashed_password}")

    # Return the salt and hashed password
    return salt.hex(), hashed_password

def verify_password(stored_password: str, stored_salt: str, provided_password: str) -> bool:
    # Combine the provided password and stored salt
    salted_password = provided_password.encode('utf-8') + bytes.fromhex(stored_salt)

    # Hash the salted password using SHA-256
    hashed_password = hashlib.sha256(salted_password).hexdigest()

    # Compare the hashed password with the stored password
    is_valid = hashed_password == stored_password
    print(f"Password is valid: {is_valid}")
    return is_valid

# Example usage
if __name__ == "__main__":
    password = 'example_password'
    salt, hashed_password = hash_password(password)
    print("Salt:", salt)
    print("Hashed Password:", hashed_password)
    print("Verify Password:", verify_password(hashed_password, salt, password))