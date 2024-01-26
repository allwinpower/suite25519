
# Suite25519 Module

Suite25519 is a cryptographic module that leverages Curve25519 for key generation, signing, verifying, encrypting, and decrypting messages. It's designed to provide a straightforward API for essential cryptographic operations.

## Installation

To use Suite25519 in your project, install it via npm:

```bash
npm install suite25519  # Assume 'suite25519' is the package name
```

## Usage

### Key Generation

Generate a new private key and derive the corresponding public key:

```javascript
import { PrivateKey } from 'suite25519';

const privateKey = PrivateKey.randomPrivateKey();
const publicKey = privateKey.publicKey;

console.log('Private Key:', privateKey.toBase64());
console.log('Public Key:', publicKey.toBase64());
```

### Signing and Verifying Messages

Sign a message with a private key and verify it with the corresponding public key:

```javascript
import { signMessage, verifyMessage } from 'suite25519';

// Sign a message
const message = 'Hello, world!';
const signature = signMessage(message, privateKey);
console.log('Signature:', signature.toString('base64'));

// Verify the signature
const isValid = verifyMessage(signature, publicKey);
console.log('Is the signature valid?', isValid);
```

### Encrypting and Decrypting Messages

Encrypt a message with a public key and decrypt it with the corresponding private key:

```javascript
import { encryptMessage, decryptMessage } from 'suite25519';

// Encrypt a message
const encryptedMessage = encryptMessage('Secret message', publicKey);
console.log('Encrypted Message:', encryptedMessage.toString('base64'));

// Decrypt the message
const decryptedMessage = decryptMessage(encryptedMessage, privateKey);
console.log('Decrypted Message:', decryptedMessage.toString('utf8'));
```

### Comprehensive Example

The following example demonstrates signing a user's public key with a master private key, verifying it, and performing encryption and decryption operations:

```javascript
import { PrivateKey, signMessage, verifyMessage, encryptMessage, decryptMessage } from 'suite25519';

function signPublicKeyWithMasterPrivateKeyExample() {
    const masterPrivateKey = PrivateKey.randomPrivateKey();
    console.log('Master Private Key:', masterPrivateKey.toBase64());
    
    const masterPublicKey = masterPrivateKey.publicKey;
    console.log('Master Public Key:', masterPublicKey.toBase64());
    
    const userPrivateKey = PrivateKey.randomPrivateKey();
    console.log('User Private Key:', userPrivateKey.toBase64());
    
    const userPublicKey = userPrivateKey.publicKey;
    console.log('User Public Key:', userPublicKey.toBase64());
    
    // Sign the user's public key
    const signature = signMessage(userPublicKey.toBase64(), masterPrivateKey);
    console.log('Signature:', signature.toString('base64'));
    
    // Verify the signature
    try {
        const verified = verifyMessage(signature, masterPublicKey);
        console.log('Verified:', verified.toString('utf8'));
    } catch (error) {
        console.error('Verification Error:', error.message);
    }
}

signPublicKeyWithMasterPrivateKeyExample();
```
