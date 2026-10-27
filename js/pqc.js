/**
 * AegisVault AI Post-Quantum Cryptography (PQC) Module
 * Implements:
 * 1. WOTS+ (Winternitz One-Time Signatures) - NIST Standard hash-based signatures.
 * 2. Ring-LWE (Learning With Errors over Rings) - Lattice-based Key Encapsulation Mechanism.
 */

import { sha256 } from './crypto.js';

// ==========================================
// WOTS+ (Winternitz One-Time Signatures)
// ==========================================

const W_BITS = 4; // Base 16 digits (Winternitz parameter w=16)
const W_VAL = 16;
const L1 = 64;    // 256 bits divided into 4-bit blocks
const L2 = 3;     // Checksum blocks (max checksum is 64 * 15 = 960, which fits in 3 hex digits)
const L_TOTAL = L1 + L2;

/**
 * Helper to hash a seed value iteratively.
 */
async function chain(value, startIndex, steps) {
  let current = value;
  for (let i = 0; i < steps; i++) {
    // Incorporate index and step count to prevent length extension attacks
    current = await sha256(current + `_wots_step_${startIndex + i}`);
  }
  return current;
}

/**
 * Generates a WOTS+ Keypair from a master seed.
 */
export async function generateWotsKeyPair(masterSeed) {
  const privateKey = [];
  const publicKey = [];
  
  // Generate L_TOTAL private key components by hashing the seed with incrementing indices
  for (let i = 0; i < L_TOTAL; i++) {
    const privComponent = await sha256(masterSeed + `_wots_priv_${i}`);
    privateKey.push(privComponent);
    
    // Public key component is the private key hashed (W_VAL - 1) times
    const pubComponent = await chain(privComponent, 0, W_VAL - 1);
    publicKey.push(pubComponent);
  }
  
  return {
    privateKey,
    publicKey // The public key can be hashed together to create a single address
  };
}

/**
 * Signs a 256-bit message hash using a WOTS+ private key.
 */
export async function signWots(messageHash, privateKey) {
  // 1. Convert message hash to 64 hex values (4 bits each)
  const digits = [];
  let checksum = 0;
  
  for (let i = 0; i < L1; i++) {
    const digit = parseInt(messageHash[i], 16);
    digits.push(digit);
    checksum += (W_VAL - 1 - digit);
  }
  
  // 2. Compute checksum blocks and append them
  const checksumHex = checksum.toString(16).padStart(L2, '0');
  for (let i = 0; i < L2; i++) {
    digits.push(parseInt(checksumHex[i], 16));
  }
  
  // 3. Create signature by chaining each private key component by its digit value
  const signature = [];
  for (let i = 0; i < L_TOTAL; i++) {
    const sigComponent = await chain(privateKey[i], 0, digits[i]);
    signature.push(sigComponent);
  }
  
  return signature;
}

/**
 * Verifies a WOTS+ signature against a public key.
 */
export async function verifyWots(messageHash, signature, publicKey) {
  try {
    const digits = [];
    let checksum = 0;
    
    for (let i = 0; i < L1; i++) {
      const digit = parseInt(messageHash[i], 16);
      digits.push(digit);
      checksum += (W_VAL - 1 - digit);
    }
    
    const checksumHex = checksum.toString(16).padStart(L2, '0');
    for (let i = 0; i < L2; i++) {
      digits.push(parseInt(checksumHex[i], 16));
    }
    
    // Check signature elements
    for (let i = 0; i < L_TOTAL; i++) {
      const neededSteps = W_VAL - 1 - digits[i];
      const verifiedComponent = await chain(signature[i], digits[i], neededSteps);
      
      if (verifiedComponent !== publicKey[i]) {
        return false; // Signature mismatch
      }
    }
    return true;
  } catch (e) {
    return false;
  }
}


// ==========================================
// Ring-LWE (Lattice-Based Key Encapsulation)
// Parameters: N = 128, q = 257 (NTRU-like toy ring)
// Modulo polynomial: x^N + 1
// Modulo prime q: 257
// ==========================================

const N = 128;
const Q = 257;
const HALF_Q = Math.floor(Q / 2);

// Polynomial representations: Array of length N
// A(x) = c0 + c1*x + c2*x^2 + ... + cN-1*x^(N-1)

/**
 * Helper to generate small random coefficients {-1, 0, 1} (Gaussian-like noise simulation)
 */
function randomSmallPoly() {
  const poly = new Int32Array(N);
  for (let i = 0; i < N; i++) {
    const val = Math.random();
    if (val < 0.33) {
      poly[i] = -1;
    } else if (val < 0.66) {
      poly[i] = 1;
    } else {
      poly[i] = 0;
    }
  }
  return poly;
}

/**
 * Generates a completely random polynomial in Z_q
 */
function randomPoly() {
  const poly = new Int32Array(N);
  for (let i = 0; i < N; i++) {
    poly[i] = Math.floor(Math.random() * Q);
  }
  return poly;
}

/**
 * Polynomial addition modulo Q
 */
function polyAdd(polyA, polyB) {
  const result = new Int32Array(N);
  for (let i = 0; i < N; i++) {
    result[i] = (polyA[i] + polyB[i]) % Q;
    if (result[i] < 0) result[i] += Q;
  }
  return result;
}

/**
 * Polynomial subtraction modulo Q
 */
function polySub(polyA, polyB) {
  const result = new Int32Array(N);
  for (let i = 0; i < N; i++) {
    result[i] = (polyA[i] - polyB[i]) % Q;
    if (result[i] < 0) result[i] += Q;
  }
  return result;
}

/**
 * Polynomial multiplication modulo (x^N + 1) and Q.
 * Ring reduction rule: x^N = -1
 */
function polyMult(polyA, polyB) {
  const result = new Int32Array(N);
  
  // Double-size array for raw multiplication expansion
  const expanded = new Int32Array(2 * N);
  
  for (let i = 0; i < N; i++) {
    for (let j = 0; j < N; j++) {
      expanded[i + j] = (expanded[i + j] + polyA[i] * polyB[j]) % Q;
    }
  }
  
  // Reduce modulo (x^N + 1): x^N = -1, x^(N+k) = -x^k
  for (let i = 0; i < N; i++) {
    result[i] = (expanded[i] - expanded[i + N]) % Q;
    if (result[i] < 0) result[i] += Q;
  }
  
  return result;
}

/**
 * Generates a Ring-LWE Key Pair.
 * Private key: s (small poly)
 * Public key: (a, b) where b = (a*s + e) mod Q
 */
export function generateRingLweKeyPair() {
  const a = randomPoly();
  const s = randomSmallPoly();
  const e = randomSmallPoly();
  
  const a_s = polyMult(a, s);
  const b = polyAdd(a_s, e);
  
  return {
    privateKey: s, // Polynomial coefficients
    publicKey: { a, b } // Two polynomials
  };
}

/**
 * Encapsulates a 128-bit key (represented as a binary polynomial of degree 128)
 * using the recipient's Ring-LWE public key.
 * Message poly: coefficients are 0 or 1.
 */
export function encapsulateRingLwe(publicKey, secretBits) {
  // Convert secret binary bits to message polynomial
  const m = new Int32Array(N);
  for (let i = 0; i < Math.min(N, secretBits.length); i++) {
    m[i] = secretBits[i] ? 1 : 0;
  }
  
  // Generate random ephemeral parameters
  const r = randomSmallPoly();
  const e1 = randomSmallPoly();
  const e2 = randomSmallPoly();
  
  // c1 = a * r + e1 mod Q
  const a_r = polyMult(publicKey.a, r);
  const c1 = polyAdd(a_r, e1);
  
  // c2 = b * r + e2 + Math.floor(Q/2) * m mod Q
  const b_r = polyMult(publicKey.b, r);
  const scaling = new Int32Array(N);
  for (let i = 0; i < N; i++) {
    scaling[i] = m[i] * HALF_Q;
  }
  const b_r_e2 = polyAdd(b_r, e2);
  const c2 = polyAdd(b_r_e2, scaling);
  
  return {
    ciphertext: { c1, c2 },
    message: m
  };
}

/**
 * Decapsulates the ciphertext using the Ring-LWE private key.
 * Recovers the 128 message bits.
 */
export function decapsulateRingLwe(ciphertext, privateKey) {
  const s = privateKey;
  const c1 = ciphertext.c1;
  const c2 = ciphertext.c2;
  
  // v = c2 - c1 * s mod Q
  const c1_s = polyMult(c1, s);
  const v = polySub(c2, c1_s);
  
  // Recover message bits:
  // If v[i] is closer to HALF_Q than 0, bit is 1. Otherwise 0.
  const decryptedBits = new Uint8Array(N);
  for (let i = 0; i < N; i++) {
    // Measure circular distance modulo Q
    const distFromHalf = Math.abs(v[i] - HALF_Q);
    const distFromZeroOrQ = Math.min(v[i], Q - v[i]);
    
    if (distFromHalf < distFromZeroOrQ) {
      decryptedBits[i] = 1;
    } else {
      decryptedBits[i] = 0;
    }
  }
  
  return decryptedBits;
}

/**
 * Converts array of 0/1 bits to Hex String
 */
export function bitsToHex(bits) {
  let hex = '';
  for (let i = 0; i < bits.length; i += 4) {
    let sum = 0;
    for (let j = 0; j < 4; j++) {
      if (bits[i + j]) {
        sum += (1 << (3 - j));
      }
    }
    hex += sum.toString(16);
  }
  return hex;
}

/**
 * Converts Hex String to array of 0/1 bits
 */
export function hexToBits(hexString) {
  const bits = new Uint8Array(N);
  let bitIdx = 0;
  for (let i = 0; i < hexString.length; i++) {
    const val = parseInt(hexString[i], 16);
    for (let j = 3; j >= 0; j--) {
      if (bitIdx < N) {
        bits[bitIdx++] = (val >> j) & 1;
      }
    }
  }
  return bits;
}
