import { PrivateKey, PublicKey, signMessage, verifyMessage, encryptMessage, signAndEncryptMessage, decryptMessage, decryptAndVerifyMessage } from './suite25519.js';

describe('Suite25519 Module Tests', () => {

    test('PrivateKey and PublicKey generation and functionality', () => {
        const privateKey = PrivateKey.randomPrivateKey();
        const publicKey = privateKey.publicKey;

        expect(privateKey).toBeDefined();
        expect(publicKey).toBeDefined();
    });

    test('Signing and verifying a message', () => {
        const privateKey = PrivateKey.randomPrivateKey();
        const publicKey = privateKey.publicKey;
        const message = 'Hello, World!';

        const signature = signMessage(message, privateKey, true, true);
        expect(signature).toBeDefined();

        const verifiedMessage = verifyMessage(signature, publicKey);
        expect(verifiedMessage).toBeInstanceOf(Buffer);
        expect(verifiedMessage.toString('utf8')).toEqual(message);
    });

    test('Encrypting and decrypting a message', () => {
        const privateKey = PrivateKey.randomPrivateKey();
        const publicKey = privateKey.publicKey;
        const message = 'Secret Message';

        const encryptedMessage = encryptMessage(message, publicKey);
        expect(encryptedMessage).toBeDefined();

        const decryptedMessage = decryptMessage(encryptedMessage, privateKey);
        expect(decryptedMessage.toString('utf8')).toEqual(message);
    });

    test('Signing, encrypting, and decrypting a message', () => {
        const senderPrivateKey = PrivateKey.randomPrivateKey();
        const recipientPrivateKey = PrivateKey.randomPrivateKey();
        const recipientPublicKey = recipientPrivateKey.publicKey;
        const message = 'Confidential Message';

        const signedAndEncryptedMessage = signAndEncryptMessage(message, senderPrivateKey, recipientPublicKey, true);
        expect(signedAndEncryptedMessage).toBeDefined();

        const decryptedAndVerifiedMessage = decryptAndVerifyMessage(signedAndEncryptedMessage, recipientPrivateKey, senderPrivateKey.publicKey);
        expect(decryptedAndVerifiedMessage.toString('utf8')).toEqual(message);
    });

    // Add more tests as necessary
});

describe('Suite25519 Module Advanced Tests', () => {
    let privateKey, publicKey;

    beforeAll(() => {
        privateKey = PrivateKey.randomPrivateKey();
        publicKey = privateKey.publicKey;
    });

    describe('Key functionality', () => {
        test('Public key derived from private key matches expected properties', () => {
            expect(publicKey).toBeDefined();
            // Assuming PublicKey has an 'id' getter to test
            expect(publicKey.id).toMatch(/[0-9a-f]{40}/i); // Example test for public key ID format
        });
    });

    describe('Message signing and verification', () => {
        const message = 'Test message';

        test('Message can be signed and verified successfully', () => {
            const signature = signMessage(message, privateKey, true, true);
            expect(signature).toBeDefined();

            const verifiedMessage = verifyMessage(signature, publicKey);
            expect(verifiedMessage.toString('utf8')).toEqual(message);
        });

        test('Verifying with wrong public key fails', () => {
            const wrongPublicKey = PrivateKey.randomPrivateKey().publicKey;
            const signature = signMessage(message, privateKey, true, true);

            expect(() => {
                verifyMessage(signature, wrongPublicKey);
            }).toThrow('Public key id does not match P');
        });
    });

    describe('Message encryption and decryption', () => {
        const message = 'Confidential message';

        test('Message can be encrypted and decrypted successfully', () => {
            const encryptedMessage = encryptMessage(message, publicKey);
            expect(encryptedMessage).toBeDefined();

            const decryptedMessage = decryptMessage(encryptedMessage, privateKey);
            expect(decryptedMessage.toString('utf8')).toEqual(message);
        });

        test('Decrypting with wrong private key fails', () => {
            const encryptedMessage = encryptMessage(message, publicKey);
            const wrongPrivateKey = PrivateKey.randomPrivateKey();

            expect(() => {
                decryptMessage(encryptedMessage, wrongPrivateKey);
            }).toThrow('Decryption failed');
        });
    });

    describe('Combined signing, encryption, and decryption', () => {
        const message = 'Sensitive information';

        test('Message can be signed, encrypted, decrypted, and verified successfully', () => {
            const recipientPrivateKey = PrivateKey.randomPrivateKey();
            const recipientPublicKey = recipientPrivateKey.publicKey;

            const signedAndEncryptedMessage = signAndEncryptMessage(message, privateKey, recipientPublicKey, true);
            expect(signedAndEncryptedMessage).toBeDefined();

            const decryptedAndVerifiedMessage = decryptAndVerifyMessage(signedAndEncryptedMessage, recipientPrivateKey, publicKey);
            expect(decryptedAndVerifiedMessage.toString('utf8')).toEqual(message);
        });
    });

    // Add more tests as needed to cover edge cases, error handling, etc.
});
