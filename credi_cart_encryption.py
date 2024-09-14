from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import logging
from datetime import datetime, timedelta

# Initialize Logger
logging.basicConfig(filename='encryption_audit.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Key Rotation and Expiration Handling
class KeyManager:
    def __init__(self):
        self.active_key = self.generate_key()
        self.keys = [(self.active_key, datetime.now())]  # Tuple of (key, creation_time)
        self.rotation_interval = timedelta(minutes=10)  # Rotate keys every 10 minutes

    def generate_key(self):
        return os.urandom(32)  # AES-256 key

    def rotate_key(self):
        new_key = self.generate_key()
        self.keys.append((new_key, datetime.now()))
        self.active_key = new_key
        logging.info("Key rotated. New key created.")

    def get_active_key(self):
        if datetime.now() - self.keys[-1][1] > self.rotation_interval:
            self.rotate_key()
        return self.active_key

    def get_key_by_time(self, timestamp):
        for key, time_created in reversed(self.keys):
            if timestamp >= time_created:
                return key
        return None  # No valid key found


# Encryption Function with Error Handling
def encrypt_card_data(card_number, key_manager):
    try:
        key = key_manager.get_active_key()
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(card_number.encode()) + encryptor.finalize()
        
        logging.info(f"Card encrypted: {mask_card_number(card_number)}")
        return ciphertext, encryptor.tag, iv, datetime.now()
    except Exception as e:
        logging.error(f"Encryption failed: {str(e)}")
        raise

# Decryption Function with Error Handling and Validation
def decrypt_card_data(ciphertext, tag, iv, timestamp, key_manager):
    try:
        key = key_manager.get_key_by_time(timestamp)
        if not key:
            raise ValueError("No valid key found for the given timestamp.")
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        logging.info("Card decrypted successfully.")
        return decrypted_data.decode()
    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        raise

# Generate a random 256-bit key for AES-256 encryption
def generate_encryption_key():
    return os.urandom(32)

# Masking Function to Hide Sensitive Information
def mask_card_number(card_number):
    return card_number[:-4].replace(card_number[:-4], '*' * len(card_number[:-4])) + card_number[-4:]

# Access Control (Simple Role Check)
def has_access(user_role):
    if user_role != 'admin':
        logging.warning(f"Unauthorized access attempt by role: {user_role}")
        raise PermissionError("You do not have permission to perform this action.")

# Main Program with Key Rotation, Expiration, and Error Handling
if __name__ == "__main__":
    key_manager = KeyManager()

    # Simulating encryption and decryption with error handling and logging
    try:
        # User role checking (admin in this case)
        user_role = 'admin'
        has_access(user_role)
        
        # Example credit card number (not real, just for testing)
        card_number = "4111111111111111"

        # Encrypt the card data
        print("Original Credit Card Number:", card_number)
        encrypted_data = encrypt_card_data(card_number, key_manager)
        ciphertext, tag, iv, timestamp = encrypted_data
        print("\nEncrypted Credit Card Data:", ciphertext)

        # Mask the credit card number
        masked_card = mask_card_number(card_number)
        print("Masked Credit Card Number:", masked_card)

        # Decrypt the card data (this would be done later, with the correct key)
        decrypted_data = decrypt_card_data(ciphertext, tag, iv, timestamp, key_manager)
        print("\nDecrypted Credit Card Number:", decrypted_data)

    except PermissionError as pe:
        print(str(pe))
    except Exception as e:
        print(f"An error occurred: {str(e)}")
