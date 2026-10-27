# AegisVault AI 🛡️⚡

> **Next-Generation Zero-Trust Blockchain dApp with Client-Side Post-Quantum Cryptography & AI Security Auditing**

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Zero Trust](https://img.shields.io/badge/Architecture-Zero--Trust-blue.svg)](#zero-trust-architecture)
[![PQC](https://img.shields.io/badge/Cryptography-Post--Quantum_(WOTS%2B_%2B_Ring--LWE)-purple.svg)](#post-quantum-cryptography-pqc)
[![Pure Vanilla JS](https://img.shields.io/badge/Stack-Vanilla_ES6_%2B_Web_Crypto_API-yellow.svg)](#technology-stack)

---

## 📌 Overview

**AegisVault AI** is a decentralized application (dApp) designed from the ground up on **Zero-Trust principles** to counter both classical vulnerabilities and emerging **"Harvest Now, Decrypt Later" (HNDL)** quantum threats.

Unlike traditional Web3 frontends that offload cryptographic operations, key storage, or AI inference to remote servers, AegisVault AI executes **100% client-side** inside the browser sandbox:
- **No Private Keys on Servers**: Keys are derived locally using PBKDF2 (100,000 rounds) and encrypted using AES-GCM (256-bit).
- **Post-Quantum Cryptography (PQC)**: Implements **Winternitz One-Time Signatures (WOTS+)** for quantum-resistant hybrid transaction signing and **Ring-LWE (Learning With Errors)** for quantum-secure Key Encapsulation (KEM).
- **Proof-of-Work Blockchain Simulation**: Features interactive Proof-of-Work mining, state ledger, mempool, and a live visual block explorer.
- **Sentry AI Agent**: Local static analyzer auditing Solidity contracts for reentrancy, integer overflows, and `tx.origin` vulnerabilities, coupled with dynamic yield portfolio optimization and a conversational cyber assistant.
- **Gamified Exploitation Arena**: An interactive visual testbed demonstrating reentrancy call recursion loops and verifying the Checks-Effects-Interactions fix.

---

## 🏛️ System Architecture

```
+-----------------------------------------------------------------------------------+
|                                 USER BROWSER                                      |
|                                                                                   |
|  +--------------------+   +---------------------+   +--------------------------+  |
|  |   UI / Dashboard   |   |   Sentry AI Agent   |   |  Reentrancy Hack Arena   |  |
|  |  (Cyber Glass UI)  |   |  (Auditor & Yield)  |   | (Visual Call Recursion)  |  |
|  +---------+----------+   +----------+----------+   +------------+-------------+  |
|            |                         |                           |                |
|  +---------v-------------------------v---------------------------v-------------+  |
|  |                              Core App Orchestrator                          |  |
|  |                                  (js/app.js)                                |  |
|  +-------------------+-----------------------------------+---------------------+  |
|                      |                                   |                        |
|  +-------------------v------------------+  +-------------v---------------------+  |
|  |       Cryptographic Engine           |  |      Virtual Blockchain & EVM     |  |
|  |          (js/crypto.js)              |  |         (js/blockchain.js)        |  |
|  |  - Web Crypto API (SubtleCrypto)     |  |  - PoW Mining Engine (Difficulty) |  |
|  |  - PBKDF2 Key Derivation (100k)      |  |  - Mempool & Block Verifier       |  |
|  |  - AES-GCM 256-bit Storage           |  |  - State Ledger (Staking, Vault)  |  |
|  |  - ECDSA (P-256) Signatures          |  +-----------------------------------+  |
|  |  - Fiat-Shamir ZK Proof Simulator    |                                         |
|  +-------------------+------------------+                                         |
|                      |                                                            |
|  +-------------------v------------------+                                         |
|  |       Post-Quantum Engine            |                                         |
|  |            (js/pqc.js)               |                                         |
|  |  - WOTS+ (Winternitz One-Time Sig)   |                                         |
|  |  - Ring-LWE Lattice KEM (N=128,q=257)|                                         |
|  |  - Hybrid Dual-Signing Validator     |                                         |
|  +--------------------------------------+                                         |
|                                                                                   |
|                   ZERO REMOTE SERVER CALLS FOR SECRETS                            |
+-----------------------------------------------------------------------------------+
```

---

## 🔒 Security & Cryptographic Highlights

### 1. Zero-Trust Architecture
- **Zero Server Trust**: The backend only serves static HTML/JS assets. No user credentials, private keys, or plaintexts are ever transmitted over the network.
- **Client-Side Key Derivation**: Private keys are derived on-the-fly from the user's master password using `PBKDF2` with SHA-256 and 100,000 iterations.
- **Zero-Knowledge Proofs (ZKP)**: Implements a non-interactive Fiat-Shamir identity proof allowing users to prove knowledge of their master password without revealing the password or its hash to the verifier.

### 2. Post-Quantum Cryptography (PQC)
To counter **Harvest Now, Decrypt Later (HNDL)** attacks where threat actors intercept encrypted communication today to decrypt it using future quantum computers (via Shor's algorithm):
- **WOTS+ (Winternitz One-Time Signatures)**: Stateless hash-chain digital signature scheme based on SHA-256. Dual-signed alongside ECDSA in PQC Hybrid Mode.
- **Ring-LWE (Learning With Errors)**: Lattice-based Key Encapsulation Mechanism (KEM) operating over polynomial ring $R_q = \mathbb{Z}_q[x]/(x^{128} + 1)$ with $q=257$. Encapsulates secret keys so only lattice private polynomials can recover them.

### 3. AI Smart Contract Auditor
Local heuristic and AST pattern engine scanning Solidity code for:
- **Reentrancy Attacks**: State modifications occurring *after* external transfer/call executions.
- **Insecure `tx.origin` Authorization**: Phishing vectors bypassing `msg.sender`.
- **Legacy Integer Overflows**: Solidity versions `< 0.8.0` without SafeMath.
- **Unchecked Return Values**: Low-level calls without status validation.

---

## 📂 Project Directory Structure

```
aegisvault-ai/
├── css/
│   └── styles.css          # Cyber-neon styling, glassmorphism, responsive grid, animations
├── js/
│   ├── ai.js               # AI static Solidity auditor, yield optimizer, Sentry chatbot
│   ├── app.js              # Central UI orchestrator, chart renderer, event bus
│   ├── blockchain.js       # Transaction, Block, and Blockchain consensus engine
│   ├── crypto.js           # Web Crypto API wrapper (PBKDF2, AES-GCM, ECDSA, ZKP)
│   └── pqc.js              # Post-quantum primitives (WOTS+, Ring-LWE lattice KEM)
├── index.html              # Main single-page web portal shell
├── package.json            # Development server configurations & scripts
├── LICENSE                 # Open-source MIT License
└── README.md               # Project documentation
```

---

## 🚀 Quick Start

AegisVault AI is completely standalone and built with modern **open-source web standards (ES6 Modules & Web Crypto API)**. No complex build pipelines or bundlers are required.

### Prerequisites
- Any modern web browser supporting the Web Crypto API (Chrome, Edge, Firefox, Brave, Safari).
- Python 3 OR Node.js (to serve files via a local HTTP server).

### Running Locally

#### Option A: Using Node.js
```bash
# Clone the repository
git clone https://github.com/<YOUR-USERNAME>/aegisvault-ai.git
cd aegisvault-ai

# Start local server
npm start
# OR
npx serve .
```

#### Option B: Using Python
```bash
# Python 3
python -m http.server 8080
```

Open your browser and navigate to:
👉 **`http://localhost:8080`**

---

## 🧪 Testing the Features

1. **Initialize Wallet**:
   - Go to **Key Management**, input a master password (`min 8 characters`), and click **Generate New Secure Wallet**.
   - Note the derived address (`0x...`) and encrypted backup payload.
2. **Toggle Post-Quantum Cryptography (PQC)**:
   - Toggle **Hybrid PQC Mode** in the header.
   - Observe the **Quantum Threat Level** drop to `0% (SECURED)` and derived WOTS+ key coordinates populate.
3. **Send & Mine Hybrid Transactions**:
   - On the **Dashboard**, transfer tokens to `0xStakingContract`.
   - Enter your master password to sign the payload with both **ECDSA** and **WOTS+**.
   - Navigate to **Block Explorer** and click **Start Block Mining Session** to solve the PoW difficulty target (`000`).
4. **Gamified Reentrancy Attack**:
   - Go to **Reentrancy Hack Arena**.
   - Click **Trigger Reentrancy Exploit** to watch the attacker drain vault liquidity via recursive fallback calls.
   - Click **Apply Security Patch** to enforce Checks-Effects-Interactions and verify that subsequent attacks are blocked.
5. **Ring-LWE Key Encapsulation**:
   - Go to **ZK Proof & Lattice KEM**.
   - Generate lattice keys, encapsulate a secret session key, and decapsulate it to verify polynomial recovery.

---

## 📜 Open Source & License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details. All cryptographic algorithms and dependencies are 100% open-source.
