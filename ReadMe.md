# Server socket protocol

### Simple serialization/deserialization socket server example

## Overview

The Advanced Secure Protocol is designed to ensure secure communication between a client and server.<br>
This implementation provides a way to securely transmit and receive command headers and data using AES encryption with GCM mode and HMAC for integrity verification.

## Features:

- **Serialization/deserialization**: Converts data to and from a transmittable format for efficient communication.
- **Secure Key Derivation**: Uses PBKDF2 with HMAC-SHA256 to derive encryption keys.
- **AES-GCM Encryption**: Ensures confidentiality and integrity of the transmitted headers and data.
- **HMAC Verification**: Provides integrity checking to prevent tampering.

**_Last Updated:_** *02.08.2024*