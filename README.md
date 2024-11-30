# Advanced Cryptography Tool

## Overview

The Advanced Cryptography Tool is a Python-based encryption and decryption utility that provides a multi-layered approach to file protection. This tool implements several cryptographic techniques to secure file contents, offering robust encryption and decryption capabilities.

## Features

- **Multiple Encryption Algorithms**:
  - Monoalphabetic Substitution Cipher
  - Vigenère Cipher
  - Vernam Cipher (One-Time Pad)
  - Transpositional Cipher
  - RSA Encryption

- **File Encryption**:
  - Supports multiple encoding strategies
  - Generates encrypted files with metadata
  - Error handling for various file types

- **Comprehensive Decryption**:
  - Multi-step decryption process
  - Reverses all encryption layers
  - Robust error handling

## Prerequisites

- Python 3.7+
- `cryptography` library
- `base64` library
- `os` module
- `random` module
- `string` module

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/raberu12/cryptography-project.git
   cd advanced-cryptography-tool
   ```

2. Install required dependencies:
   ```bash
   pip install cryptography
   ```

## Usage

### Interactive Mode

Run the script to use the interactive menu:

```bash
python advanced_crypto_tool.py
```

### Menu Options

1. **Encrypt a File**
   - Select option 1
   - Enter the filename you want to encrypt
   - Encrypted file will be saved with `.enc` extension

2. **Decrypt a File**
   - Select option 2
   - Enter the encrypted filename
   - Decrypted content will be saved as `decrypted.txt`

3. **Exit**
   - Select option 3 to close the application

## Encryption Process

The tool applies multiple encryption layers in sequence:
1. Monoalphabetic Substitution
2. Vigenère Cipher
3. Vernam Cipher
4. Transpositional Cipher
5. RSA Key Encryption

## Security Notes

- RSA keys are generated dynamically for each session
- Private and public keys are saved as `private_key.pem` and `public_key.pem`
- Encryption includes error handling for various file types and encodings

## Limitations

- File size is limited (max 190 characters for RSA encryption)
- Designed for text files
- Encryption keys are not persistent between sessions

## Disclaimer

This tool is for educational purposes. Always ensure you have proper authorization before encrypting or decrypting files.