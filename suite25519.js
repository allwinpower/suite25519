import { ed25519, x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { siv } from '@noble/ciphers/aes';
import { utf8ToBytes, bytesToUtf8, hexToBytes, bytesToHex } from '@noble/ciphers/utils';
import { randomBytes } from 'crypto';

//This function converts a byte array to a Base64 URL encoded string.
function bytesToBase64(bytes) {
    let base64;
    if (typeof Buffer === 'function') {
        // Node.js environment
        base64 = Buffer.from(bytes).toString('base64');
    } else {
        // Browser environment
        const binaryString = new Uint8Array(bytes).reduce((acc, byte) => acc + String.fromCharCode(byte), '');
        base64 = window.btoa(binaryString);
    }
    return base64;
}

//This function converts a Base64 URL encoded string back to a byte array.
function Base64ToBytes(base64url) {
    //return hexToBytes(base64url);
    let binaryString;
    base64url = base64url.replace(/-/g, '+').replace(/_/g, '/');

    if (typeof Buffer === 'function') {
        // Node.js environment
        binaryString = Buffer.from(base64url, 'base64').toString('binary');
    } else {
        // Browser environment
        binaryString = window.atob(base64url);
    }

    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }

    return bytes;
}

function stringToBase64(str) {
    return bytesToBase64(utf8ToBytes(str)); // Reuse your existing bytesToBase64 function
}

function base64ToString(base64url) {
    const bytes = Base64ToBytes(base64url); // Reuse your existing Base64ToBytes function

    if (typeof TextDecoder === 'function') {
        // Browser environment
        return new TextDecoder().decode(bytes);
    } else {
        // Node.js environment
        return Buffer.from(bytes).toString();
    }
}

function validatePublicKeyObject(publicKeyObject) {
    let publicKey, sig, valid;

    try {
        publicKey = hexToBytes(publicKeyObject.P);
    }
    catch (error) {
        throw new Error(`publicKeyObject.P ${error?.message}`);
    }

    try {
        sig = hexToBytes(publicKeyObject.Sig);
    }
    catch (error) {
        throw new Error(`publicKeyObject.Sig ${error?.message}`);
    }

    try {
        valid = ed25519.verify(sig, publicKey, publicKey, { zip215: false }); // RFC8032 / FIPS 186-5
    }
    catch (error) {
        throw new Error(`ed25519.verify ${error?.message}`);
    }

    if (!valid) {
        throw new Error('ed25519.verify Invalid Signature');
    }
}

function eciesEncrypt(receiverPublicKeyEd, messageBinary) {
    try {

        // Convert Keys
        //const receiverPublicKeyEd = publicKeyObject.P;
        const receiverPublicKeyX = edwardsToMontgomeryPub(receiverPublicKeyEd);

        //Generate ephemeral key pair
        const ephemeralPrivateKeyX = x25519.utils.randomPrivateKey();
        const ephemeralPublicKeyX = x25519.getPublicKey(ephemeralPrivateKeyX);

        // Derive shared secret using ECDH
        const sharedSecret = x25519.getSharedSecret(ephemeralPrivateKeyX, receiverPublicKeyX);

        // Use a part of the shared secret as the AES key
        const aesKey = sharedSecret.slice(0, 32); // AES key length

        // Generate a random nonce for AES
        const nonce = randomBytes(12); // 12 bytes is typical for GCM

        // Encrypt the plaintext
        const aes = siv(aesKey, nonce);
        const ciphertext = aes.encrypt(messageBinary);

        // Return the ephemeral public key, nonce, and ciphertext
        return { C: ciphertext, P_e: ephemeralPublicKeyX, N: nonce };
    }
    catch (error) {
        throw new Error(`eciesEncrypt ${error?.message}`);
    }
}

export function eciesDecrypt(receiverPrivateKeyEd, ephemeralPublicKeyX, nonce, ciphertext) {
    try {
        const receiverPrivateKeyX = edwardsToMontgomeryPriv(receiverPrivateKeyEd);
        // Derive shared secret
        const sharedSecret = x25519.getSharedSecret(receiverPrivateKeyX, ephemeralPublicKeyX);

        // Use a part of the shared secret as the AES key
        const aesKey = sharedSecret.slice(0, 32);

        // Decrypt the ciphertext
        const aes = siv(aesKey, nonce);
        let plaintext;
        try {
            plaintext = aes.decrypt(ciphertext);
        } catch (error) {
            throw new Error('Decryption failed');
        }

        return plaintext;
    }
    catch (error) {
        throw new Error(`eciesDecrypt ${error?.message}`);
    }
}

export class BinaryData {

    constructor(data) {
        this.data = data;
    }

    static fromBase64(encodedData) {
        const data = Base64ToBytes(encodedData);
        if (this.objectIdentifier) {
            return new this(data);
        }
        throw new Error('Unsupported type for fromString method.');
    }

    static fromObject(object) {
        if (object && this.objectIdentifier && object[this.objectIdentifier]) {
            const data = Base64ToBytes(object[this.objectIdentifier]);
            return new this(data);
        } else {
            throw new Error(`Invalid object format for ${this.name}.`);
        }
    }

    toBinary() {
        return this.data;
    }

    toBase64() {
        return bytesToBase64(this.data);
    }

    toObject() {
        const obj = {};
        obj[this.constructor.objectIdentifier] = this.toBase64();
        return obj;
    }

    toJSON() {
        return this.toObject();
    }
}

class EphemeralPublicKey extends BinaryData {
    static objectIdentifier = 'P_e';
}

class Nonce extends BinaryData {
    static objectIdentifier = 'N';
}

class Cipher extends BinaryData {
    static objectIdentifier = 'C';
}

export class CipherEnvelope {

    constructor(ephemeralPublicKey, nonce, cipher) {
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.nonce = nonce;
        this.cipher = cipher;
    }

    static fromBase64(base64Envelope) {
        try {
            const jsonEnvelope = base64ToString(base64Envelope);
            const objectEnvelope = JSON.parse(jsonEnvelope);
            return CipherEnvelope.fromObject(objectEnvelope);
        }
        catch (error) {
            throw error;
        }
    }

    static fromObject(object) {
        try {
            return new CipherEnvelope(
                EphemeralPublicKey.fromObject(object),
                Nonce.fromObject(object),
                Cipher.fromObject(object)
            );
        }
        catch (error) {
            throw error;
        }
    }

    toBase64() {
        return stringToBase64(JSON.stringify(this.toObject()));
    }

    toObject() {
        return {
            ...this.ephemeralPublicKey.toObject(),
            ...this.nonce.toObject(),
            ...this.cipher.toObject(),
        };
    }

    toJSON() {
        return this.toObject();
    }
}

export class Message extends BinaryData {
    static objectIdentifier = 'm';

    static load(message) {
        let data;
        if (message instanceof Message) {
            // Message is already an instance of Message, use its binary data
            data = message.message;
        } else if (message instanceof Uint8Array) {
            // Data is already in binary format, use it as is
            data = message;
        } else if (typeof message === 'object' || Array.isArray(message)) {
            // Data is an object or array, convert to JSON string and then encode
            const jsonString = JSON.stringify(message);
            data = utf8ToBytes(jsonString);
        } else if (typeof message === 'string') {
            // Data is a string, encode it
            data = utf8ToBytes(message);
        } else {
            // Unsupported data type
            throw new Error('Invalid data type for message. Expected Uint8Array, object, array, string, or Message.');
        }
        return new Message(data);
    }

    static randomBytes(length) {
        return new Message(randomBytes(length));
    }

    toString() {
        return bytesToUtf8(this.data);
    }
}

export class Signature extends BinaryData {
    static objectIdentifier = 's';
}

export class EncryptedSignedEnvelope {
    constructor(cipher, signature, publicKey) {
        this.cipher = cipher;
        this.signature = signature;
        this.publicKey = publicKey;
    }

    verify() {
        try {
            return this.publicKey.verify(Message.load(this.cipher.toBase64()), this.signature);
        }
        catch (error) {
            throw error;
        }
    }

    decrypt(privateKey) {
        if (!(privateKey instanceof PrivateKey)) {
            throw new Error("The provided object is not an instance of PrivateKey.");
        }
        try {
            if (this.verify()) {
                return privateKey.decrypt(this.cipher);

            }
        }
        catch (error) {
            throw error;
        }
    }

    static encrypt(data, privateKey, publicKey) {
        if (!(data instanceof Message)) {
            throw new Error("The provided object is not an instance of Message.");
        }

        const cipherData = publicKey.encrypt(data);
        const signedCipher = privateKey.sign(Message.load(cipherData.toBase64()));

        return new EncryptedSignedEnvelope(
            cipherData,
            signedCipher,
            publicKey
        );

    }

    static fromBase64(base64Envelope) {
        try {
            const jsonEnvelope = base64ToString(base64Envelope);
            const objectEnvelope = JSON.parse(jsonEnvelope);
            return EncryptedSignedEnvelope.fromObject(objectEnvelope);
        }
        catch (error) {
            throw error;
        }
    }

    static fromObject(object) {
        try {
            return new EncryptedSignedEnvelope(
                CipherEnvelope.fromObject(object),
                Signature.fromObject(object),
                PublicKey.fromObject(object)
            );
        }
        catch (error) {
            throw error;
        }
    }

    toBase64() {
        return stringToBase64(JSON.stringify(this.toObject()));
    }

    toObject() {
        return {
            ...this.cipher.toObject(),
            ...this.publicKey.toObject(),
            ...this.signature.toObject()
        };
    }

    toJSON() {
        return this.toObject();
    }
}

export class PublicKey extends BinaryData {
    static objectIdentifier = 'P';

    static loadKey(encodedPublicKey) {
        // Logic to validate and load keyData
        try {
            const keyData = Base64ToBytes(encodedPublicKey);
            return new PrivateKey(keyData);
        }
        catch (error) {
            throw error;
        }
    }

    get id() {
        return bytesToHex(ripemd160(this.toBinary()));
    }

    verify(data, signature) {
        if (!(data instanceof Message)) {
            throw new Error("The provided object is not an instance of Message.");
        }

        if (!(signature instanceof Signature)) {
            throw new Error("The provided object is not an instance of Signature.");
        }

        // Logic to verify the signature using this.keyData
        let valid = ed25519.verify(signature.toBinary(), data.toBinary(), this.toBinary(), { zip215: false }); // RFC8032 / FIPS 186-5
        if (!valid) {
            throw new Error('Signature invalid');
        }
        else {
            return true;
        }
    }

    encrypt(data) {
        if (!(data instanceof Message)) {
            throw new Error("The provided object is not an instance of Message.");
        }

        const cipher = eciesEncrypt(this.toBinary(), data.toBinary());
        return new CipherEnvelope(
            new EphemeralPublicKey(cipher.P_e),
            new Nonce(cipher.N),
            new Cipher(cipher.C)
        );
    }
}

export class PublicKeyEnvelope {

    constructor(publicKey, signature) {
        this.publicKey = publicKey;
        this.signature = signature;
    }

    verify() {
        try {
            // Wrap public key in a message object
            const msg = new Message(this.publicKey.toBinary());
            return this.publicKey.verify(msg, this.signature);
        }
        catch (error) {
            throw error;
        }
    }

    static fromBase64(base64Envelope) {
        try {
            const jsonEnvelope = base64ToString(base64Envelope);
            const objectEnvelope = JSON.parse(jsonEnvelope);
            return PublicKeyEnvelope.fromObject(objectEnvelope);
        }
        catch (error) {
            throw error;
        }
    }

    static fromObject(object) {
        try {
            return new PublicKeyEnvelope(
                PublicKey.fromObject(object),
                Signature.fromObject(object)
            );
        }
        catch (error) {
            throw error;
        }
    }

    toBase64() {
        return stringToBase64(JSON.stringify(this.toObject()));
    }

    toObject() {
        return {
            ...this.publicKey.toObject(),
            ...this.signature.toObject()
        };
    }

    toJSON() {
        return this.toObject();
    }
}

export class PrivateKey extends BinaryData {
    static objectIdentifier = 'k';

    static new() {
        // Logic to generate a new key
        const keyData = ed25519.utils.randomPrivateKey();
        return new PrivateKey(keyData);
    }

    static loadKey(encodedPrivateKey) {
        // Logic to validate and load keyData
        try {
            const keyData = Base64ToBytes(encodedPrivateKey);
            return new PrivateKey(keyData);
        }
        catch (error) {
            throw error;
        }
    }

    get publicKey() {
        const publicKeyData = ed25519.getPublicKey(this.data);
        return new PublicKey(publicKeyData);
    }

    get publicKeyEnvelope() {
        // Wrap public key in message object before signing
        const msg = new Message(this.publicKey.toBinary());
        const sig = this.sign(msg);
        return new PublicKeyEnvelope(this.publicKey, sig);
    }

    decrypt(envelope) {
        if (!(envelope instanceof CipherEnvelope)) {
            throw new Error("The provided object is not an instance of Envelope.");
        }
        try {
            const m = eciesDecrypt(
                this.toBinary(),
                envelope.ephemeralPublicKey.toBinary(),
                envelope.nonce.toBinary(),
                envelope.cipher.toBinary()
            );
            return new Message(m);
        }
        catch (error) {
            throw error;
        }
    }

    sign(message) {
        if (!(message instanceof Message)) {
            throw new Error("The provided object is not an instance of Message.");
        }
        const sigData = ed25519.sign(message.toBinary(), this.data);

        return new Signature(sigData);
    }

    toBase64() {
        return bytesToBase64(this.data);
    }

    toJSON() {
        return {
            k: this.toBase64()
        };
    }
}