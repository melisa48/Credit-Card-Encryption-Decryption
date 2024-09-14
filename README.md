# Credit Card Encryption and Decryption
This project implements a secure system for encrypting and decrypting credit card numbers using AES-256 encryption. It is designed to be used by financial institutions and e-commerce platforms to protect sensitive payment data, ensuring compliance with PCI DSS (Payment Card Industry Data Security Standard) regulations. The system includes advanced features such as key rotation, expiration, error handling, and compliance logging.

## Features
- AES-256 Encryption and Decryption: Utilizes AES encryption with GCM mode for secure data protection.
- Key Rotation and Expiration: Implements key management with periodic key rotation and expiration handling.
- Error Handling: Includes comprehensive error handling for encryption and decryption failures.
- Compliance Features: Logs encryption, decryption, and key management activities; includes basic access control.

## Installation
1. Clone the Repository:
- `git clone <repository-url>`
- `cd <repository-directory>`
2.  Install Dependencies: Make sure you have Python installed. Install the required Python package using `pip`:
- `pip install cryptography`

## Usage
1. Run the Script: To execute the script, use the following command:
`python credi_cart_encryption.py`
2. Script Behavior:
- The script will display the original credit card number.
- It will encrypt the card number and show the encrypted data.
- The masked version of the credit card number will be displayed.
- Finally, the script will decrypt the data and show the original credit card number.
## Key Management
- Key Rotation: Keys are rotated every 10 minutes. Older keys are retained for decrypting previously encrypted data.
- Key Expiration: The system checks if the current key has expired and rotates it if necessary.

## Logging and Compliance
- Logs: Encryption and decryption operations, key rotations, and access control attempts are logged to encryption_audit.log.
- Access Control: A simple role-based access control is implemented. Only users with the 'admin' role can perform encryption and decryption.

## Contributing
- Feel free to open issues or submit pull requests if you have suggestions or improvements for this project.
