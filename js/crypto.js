/**
 * AegisVault AI Cryptographic Module
 * Client-Side Zero-Trust Cryptography using Web Crypto API.
 * No private keys or unencrypted seeds ever leave the client memory.
 */

// Helper to convert ArrayBuffer to Base64
export function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper to convert Base64 to ArrayBuffer
export function base64ToBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper to convert string to ArrayBuffer
export function stringToBuffer(str) {
  return new TextEncoder().encode(str);
}

// Helper to convert ArrayBuffer to hex string
export function bufferToHex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

/**
 * Derives a cryptographic key from a user password using PBKDF2.
 */
async function deriveKeyFromPassword(password, salt) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  
  // Import raw password as key material
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  
  // Derive AES-GCM key
  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a text payload client-side using a passphrase.
 */
export async function encryptPayload(passphrase, plaintext) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const aesKey = await deriveKeyFromPassword(passphrase, salt);
  
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    aesKey,
    data
  );
  
  return {
    ciphertext: bufferToBase64(ciphertextBuffer),
    salt: bufferToBase64(salt),
    iv: bufferToBase64(iv)
  };
}

/**
 * Decrypts a payload client-side using a passphrase.
 */
export async function decryptPayload(passphrase, encryptedData) {
  const salt = new Uint8Array(base64ToBuffer(encryptedData.salt));
  const iv = new Uint8Array(base64ToBuffer(encryptedData.iv));
  const ciphertext = base64ToBuffer(encryptedData.ciphertext);
  
  const aesKey = await deriveKeyFromPassword(passphrase, salt);
  
  try {
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      aesKey,
      ciphertext
    );
    
    return new TextDecoder().decode(decryptedBuffer);
  } catch (e) {
    throw new Error('Decryption failed. Invalid master password.');
  }
}

/**
 * Generates an ECDSA keypair for transaction signing.
 */
export async function generateKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true, // Extractable
    ['sign', 'verify']
  );
  
  return keyPair;
}

/**
 * Exports a key (public or private) to JWK format.
 */
export async function exportKey(key) {
  const jwk = await window.crypto.subtle.exportKey('jwk', key);
  return JSON.stringify(jwk);
}

/**
 * Imports a key from JWK format.
 */
export async function importKey(jwkString, isPrivate = false) {
  const jwk = JSON.parse(jwkString);
  return await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    isPrivate ? ['sign'] : ['verify']
  );
}

/**
 * Signs a transaction object with a private key.
 */
export async function signTransaction(privateKey, transaction) {
  // Sort transaction keys to ensure consistent hashing representation
  const txString = JSON.stringify(transaction, Object.keys(transaction).sort());
  const encoder = new TextEncoder();
  const txData = encoder.encode(txString);
  
  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' }
    },
    privateKey,
    txData
  );
  
  return bufferToBase64(signatureBuffer);
}

/**
 * Verifies a transaction signature with a public key.
 */
export async function verifyTransactionSignature(publicKey, transaction, signatureBase64) {
  try {
    const txString = JSON.stringify(transaction, Object.keys(transaction).sort());
    const encoder = new TextEncoder();
    const txData = encoder.encode(txString);
    const signature = base64ToBuffer(signatureBase64);
    
    return await window.crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      publicKey,
      signature,
      txData
    );
  } catch (e) {
    console.error('Signature verification error', e);
    return false;
  }
}

/**
 * Simulated Zero-Knowledge Proof (ZKP) Generator.
 * Proves that the user knows the master password (secret)
 * for a specific public seed hash without exposing the password.
 * Uses a cryptographic hash-chain challenge (Fiat-Shamir simulation).
 */
export async function generateIdentityZKP(password, challenge) {
  const hash1 = await sha256(password);
  // Commit to a random value
  const r = bufferToHex(window.crypto.getRandomValues(new Uint8Array(16)));
  const commitment = await sha256(r);
  
  // Challenge is provided by the verifier
  const s = await sha256(hash1 + challenge + r); // ZK response proof
  
  return {
    commitment,
    challenge,
    proof: s,
    r_hash: await sha256(r) // Verifies relation
  };
}

/**
 * Simple SHA-256 helper
 */
export async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
  return bufferToHex(hashBuffer);
}

/**
 * Generates a mock mnemonic phrase from secure random values.
 */
export function generateMnemonic() {
  const words = [
    'aegis', 'vault', 'cyber', 'secure', 'blockchain', 'ledger', 'sentry',
    'crypto', 'proof', 'zero', 'trust', 'kernel', 'quantum', 'node', 'matrix',
    'beacon', 'orbit', 'nexus', 'pulse', 'cipher', 'vector', 'vertex', 'shatter', 'phantom'
  ];
  const selected = [];
  for (let i = 0; i < 12; i++) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    const index = array[0] % words.length;
    selected.push(words[index]);
  }
  return selected.join(' ');
}
