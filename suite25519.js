import { ed25519, x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { siv } from '@noble/ciphers/aes';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes, sign } from 'crypto';
import cbor from 'cbor';

const assertType = (variableObj, type) => {
    const [variableName, variable] = Object.entries(variableObj)[0];
    if (typeof variable !== type && !(variable instanceof type)) {
        throw new Error(`${variableName} is not an instance of [${type.name || type}].`);
    }
};

function alignBy4(input) {
    const misalignment = input.byteOffset % 4;
    if (misalignment === 0) return input;
    const u32Size = input.length + (misalignment === 0 ? 0 : 4 - misalignment);
    const uint32 = new Uint32Array(u32Size / 4);
    const uint8 = new Uint8Array(uint32.buffer);
    uint8.set(input);
    return uint8;
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

function eciesDecrypt(receiverPrivateKeyEd, ephemeralPublicKeyX, nonce, ciphertext) {
    try {
        ephemeralPublicKeyX = alignBy4(ephemeralPublicKeyX);
        nonce = alignBy4(nonce);
        ciphertext = alignBy4(ciphertext);

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
            console.log('eciesDecrypt', error);
            throw new Error('Decryption failed');
        }

        return plaintext;
    }
    catch (error) {
        throw new Error(`eciesDecrypt ${error?.message}`);
    }
}

class BinaryData {

    constructor(data) {
        this.data = data;
    }

    static fromBase64(base64) {
        const data = cbor.decode(Buffer.from(base64, 'base64'));
        //console.log('DEBUG IMPORT:', data);
        if (data[this.objectIdentifier]) {
            return new this(data[this.objectIdentifier]);
        }
        throw new Error('Unsupported type for method.');
    }

    static fromObject(object) {
        if (object && this.objectIdentifier && object[this.objectIdentifier]) {
            const data = Buffer.from(object[this.objectIdentifier], 'base64');
            return new this(data);
        } else {
            throw new Error(`Invalid object format for ${this.name}.`);
        }
    }

    toBinary() {
        return this.data;
    }

    #toCbor() {
        const obj = {};
        obj[this.constructor.objectIdentifier] = this.toBinary();
        return cbor.encode(obj);
    }

    toBase64() {
        return Buffer.from(this.#toCbor()).toString('base64');
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

class Signature extends BinaryData {
    static objectIdentifier = 's';
}

class Message extends BinaryData {
    static objectIdentifier = 'm';

    constructor(data) {
        if (data instanceof Uint8Array) {
            super(data);
        } else if (typeof data === 'string') {
            super(Buffer.from(data, 'utf8'));
        } else {
            // Include the type of the invalid data in the error message
            let dataType = typeof data;
            if (data && typeof data === 'object') {
                dataType = data.constructor.name; // More specific type for objects
            }
            throw new Error(`Invalid data type for Message: ${dataType}`);
        }
    }

    static randomBytes(length) {
        return new Message(randomBytes(length));
    }

    toString() {
        return Buffer.toString(this.data);
    }
}

class CipherEnvelope {

    constructor(ephemeralPublicKey, nonce, cipher, signature, publicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.nonce = nonce;
        this.cipher = cipher;
        this.signature = signature;
        this.publicKey = publicKey;
    }

    static fromBase64(base64Envelope) {
        try {
            const jsonEnvelope = Buffer.from(base64Envelope, 'base64');
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

    #toObject() {
        return {
            ...this.ephemeralPublicKey.toObject(),
            ...this.nonce.toObject(),
            ...this.cipher.toObject(),
        };
    }

    toBase64() {
        return stringToBase64(JSON.stringify(this.#toObject()));
    }

    toJSON() {
        return this.#toObject();
    }
}

export class PrivateKey extends BinaryData {
    static objectIdentifier = 'k';

    static randomPrivateKey() {
        return new PrivateKey(ed25519.utils.randomPrivateKey());
    }

    get publicKey() {
        const publicKeyData = ed25519.getPublicKey(this.data);
        return new PublicKey(publicKeyData);
    }

    get publicKeyEnvelope() {
        return PublicKeyEnvelope.sign(this.publicKey, this);
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

    toJSON() {
        return {
            k: this.toBase64()
        };
    }
}

export class PublicKey extends BinaryData {
    static objectIdentifier = 'P';

    get id() {
        return Buffer.from(ripemd160(this.toBinary())).toString('hex');
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

/* New version */
class baseEnvelope {
    toBase64() {
        return Buffer.from(JSON.stringify(this.toObject())).toString('base64');
    }
}

class SignatureEnvelope extends baseEnvelope {
    #signature;
    constructor(signature) {
        super();
        if (!(signature instanceof Signature)) {
            throw new Error(`signature[${signature.constructor.name}] is not an instance of [Signature].`);
        }
        this.#signature = signature;
    }

    toObject() {
        return {
            s: this.#signature.toBase64()
        };
    }
}

class SignaturePublicKeyEnvelope extends SignatureEnvelope {
    #publicKey;
    constructor(signature, publicKey) {
        super(signature);
        if (!(publicKey instanceof PublicKey)) {
            throw new Error(`publicKey[${publicKey.constructor.name}] is not an instance of [PublicKey].`);
        }
        this.#publicKey = publicKey;
    }

    toObject() {
        return {
            ...super.toObject(),
            ...this.#publicKey.toObject()
        };
    }
}

class EciesEnvelope extends baseEnvelope {
    #ephemeralPublicKey;
    #cipher;
    #nonce;

    constructor(cipher, nonce, ephemeralPublicKey) {
        super();
        if (!(ephemeralPublicKey instanceof EphemeralPublicKey)) {
            throw new Error(`ephemeralPublicKey[${ephemeralPublicKey.constructor.name}] is not an instance of [EphemeralPublicKey].`);
        }
        if (!(cipher instanceof Cipher)) {
            throw new Error(`cipher[${cipher.constructor.name}] is not an instance of [Cipher].`);
        }
        if (!(nonce instanceof Nonce)) {
            throw new Error(`nonce[${nonce.constructor.name}] is not an instance of [Nonce].`);
        }
        this.#ephemeralPublicKey = ephemeralPublicKey;
        this.#cipher = cipher;
        this.#nonce = nonce;
    }

    toObject() {
        return {
            ...this.#ephemeralPublicKey.toObject(),
            ...this.#cipher.toObject(),
            ...this.#nonce.toObject()
        };
    }
}

export const signMessage = (plainMessage, signingPrivateKey, includeMessage = false, includeSenderPublicKey = false) => {
    try {
        assertType({ signingPrivateKey }, PrivateKey);
        assertType({ includeMessage }, 'boolean');
        assertType({ includeSenderPublicKey }, 'boolean');

        const message = new Message(plainMessage);
        const messageBinary = message.toBinary();

        const result = {
            sig: ed25519.sign(messageBinary, signingPrivateKey.toBinary()),
            ...(includeMessage && { m: messageBinary }),
            ...(includeSenderPublicKey && { P: signingPrivateKey.publicKey.toBinary() })
        };

        return Buffer.from(cbor.encode(result));
    }
    catch (error) {
        throw error;
    }
}
export const verifyMessage = (signedMessage, senderPublicKey) => {
    assertType({ senderPublicKey }, PublicKey);

    const { sig, m, P } = cbor.decode(signedMessage);

    if (!senderPublicKey) {
        throw new Error('senderPublicKey is required');
    }

    // If P is provided, verify that its id matches senderPublicKey's id
    if (P && new PublicKey(P).id !== senderPublicKey.id) {
        throw new Error('Public key id does not match P');
    }

    const message = new Message(m);
    const signature = new Signature(sig);

    if (!senderPublicKey.verify(message, signature)) {
        throw new Error('Invalid signature');
    }

    return message.toBinary();
};

export const encryptMessage = (plainMessage, recipientPublicKey) => {
    try {
        assertType({ recipientPublicKey }, PublicKey);

        const message = new Message(plainMessage);
        const cipher = eciesEncrypt(recipientPublicKey.toBinary(), message.toBinary());

        return Buffer.from(cbor.encode(cipher));
    }
    catch (error) {
        throw error;
    }
}

export const decryptMessage = (cipher, recipientPrivateKey) => {
    try {
        assertType({ recipientPrivateKey }, PrivateKey);

        let { C, P_e, N } = cbor.decode(cipher);

        const message = eciesDecrypt(recipientPrivateKey.toBinary(), P_e, N, C);
        return Buffer.from(message);
    }
    catch (error) {
        throw error;
    }

}

export const signAndEncryptMessage = (plainMessage, signingPrivateKey, recipientPublicKey, includeSenderPublicKey) => {
    try {
        assertType({ signingPrivateKey }, PrivateKey);
        assertType({ recipientPublicKey }, PublicKey);
        assertType({ includeSenderPublicKey }, 'boolean');

        const Sig_m = signMessage(plainMessage, signingPrivateKey, true, includeSenderPublicKey);
        return Buffer.from(encryptMessage(Sig_m, recipientPublicKey));
    }
    catch (error) {
        throw error;
    }
}

export const decryptAndVerifyMessage = (cipher, recipientPrivateKey, senderPublicKey) => {
    try {
        assertType({ recipientPrivateKey }, PrivateKey);
        assertType({ senderPublicKey }, PublicKey);

        const Sig_m = decryptMessage(cipher, recipientPrivateKey);
        const { sig, m, P } = cbor.decode(Sig_m);

        const message = new Message(m);
        const signature = new Signature(sig);
        const publicKey = new PublicKey(P);

        if (publicKey.id !== senderPublicKey.id) {
            throw new Error('Invalid sender public key');
        }

        if (!publicKey.verify(message, signature)) {
            throw new Error('Invalid signature');
        }

        return message.toBinary();
    }
    catch (error) {
        throw error;
    }
}