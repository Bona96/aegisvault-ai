import { sha256, verifyTransactionSignature } from './crypto.js';
import { verifyWots } from './pqc.js';

export class Transaction {
  constructor(fromAddress, toAddress, amount, gas = 1, nonce = 0) {
    this.fromAddress = fromAddress;
    this.toAddress = toAddress;
    this.amount = Number(amount);
    this.gas = Number(gas);
    this.nonce = Number(nonce);
    this.timestamp = Date.now();
    
    // Classical Cryptography
    this.signature = null; 
    
    // Post-Quantum Cryptography (PQC)
    this.wotsSignature = null;
    this.wotsPublicKey = null; // Stored to verify quantum resistance
    this.pqcEnabled = false;
  }

  async calculateHash() {
    return await sha256(
      this.fromAddress +
      this.toAddress +
      this.amount +
      this.gas +
      this.nonce +
      this.timestamp
    );
  }

  // Signs transaction using public JWK and Private Key CryptoKey, and WOTS+ key if enabled
  async sign(privateKey, publicJwkString, wotsKeyPair = null) {
    const hash = await this.calculateHash();
    // Enforce that you can only sign transactions originating from your public key wallet
    const address = await sha256(publicJwkString);
    const shortAddress = '0x' + address.slice(0, 40);
    
    if (this.fromAddress !== shortAddress) {
      throw new Error("Cannot sign transactions for other wallets!");
    }

    const txObject = {
      fromAddress: this.fromAddress,
      toAddress: this.toAddress,
      amount: this.amount,
      gas: this.gas,
      nonce: this.nonce,
      timestamp: this.timestamp
    };
    
    const { signTransaction } = await import('./crypto.js');
    this.signature = await signTransaction(privateKey, txObject);

    // Hybrid Post-Quantum Sign
    if (wotsKeyPair) {
      const { signWots } = await import('./pqc.js');
      this.wotsSignature = await signWots(hash, wotsKeyPair.privateKey);
      this.wotsPublicKey = wotsKeyPair.publicKey;
      this.pqcEnabled = true;
    }
  }

  async isValid() {
    if (this.fromAddress === 'SYSTEM-MINT') return true; // Mining reward
    if (!this.signature) return false;

    // 1. Verify Classical ECDSA Signature
    const activePublicKey = window.activeWalletPublicKey;
    if (!activePublicKey) return false; 

    const txObject = {
      fromAddress: this.fromAddress,
      toAddress: this.toAddress,
      amount: this.amount,
      gas: this.gas,
      nonce: this.nonce,
      timestamp: this.timestamp
    };

    const classicalValid = await verifyTransactionSignature(activePublicKey, txObject, this.signature);
    if (!classicalValid) return false;

    // 2. Verify Post-Quantum Signature if transaction has PQC enabled or if system enforces it
    if (this.pqcEnabled) {
      if (!this.wotsSignature || !this.wotsPublicKey) return false;
      const hash = await this.calculateHash();
      const pqcValid = await verifyWots(hash, this.wotsSignature, this.wotsPublicKey);
      return pqcValid;
    }

    return true;
  }
}

export class Block {
  constructor(timestamp, transactions, previousHash = '') {
    this.timestamp = timestamp;
    this.transactions = transactions;
    this.previousHash = previousHash;
    this.hash = '';
    this.nonce = 0;
  }

  async calculateHash() {
    const txHashes = [];
    for (const tx of this.transactions) {
      const h = tx.signature || await tx.calculateHash();
      txHashes.push(h);
    }
    
    return await sha256(
      this.previousHash +
      this.timestamp +
      JSON.stringify(txHashes) +
      this.nonce
    );
  }

  async mineBlock(difficulty, onProgress) {
    const target = Array(difficulty + 1).join("0");
    this.hash = await this.calculateHash();
    
    let iterations = 0;
    while (this.hash.substring(0, difficulty) !== target) {
      this.nonce++;
      this.hash = await this.calculateHash();
      iterations++;
      
      if (iterations % 200 === 0) {
        onProgress({ nonce: this.nonce, hash: this.hash });
        await new Promise(resolve => setTimeout(resolve, 10)); // Yield to thread
      }
    }
    return this.hash;
  }
}

export class Blockchain {
  constructor() {
    this.chain = [];
    this.difficulty = 3;
    this.pendingTransactions = [];
    this.miningReward = 100;
    this.systemLogs = [];
    
    // Smart Contract states
    this.contractsState = {
      staking: {
        totalStaked: 0,
        stakes: {} // address -> amount
      },
      multisig: {
        owners: [],
        requiredConfirmations: 2,
        proposals: [] 
      },
      yieldOptimizer: {
        poolAllocation: { safe: 100, moderate: 0, aggressive: 0 },
        totalValueLocked: 0,
        history: []
      }
    };
  }

  async init() {
    // Create Genesis block
    const genesisTx = new Transaction('SYSTEM-MINT', '0xAegisVaultGenesisWallet', 1000000, 0, 0);
    const genesisBlock = new Block(Date.parse("2026-07-12"), [genesisTx], "0000000000000000000000000000000000000000000000000000000000000000");
    genesisBlock.hash = await genesisBlock.calculateHash();
    this.chain.push(genesisBlock);
    this.log("System initialized. Genesis block created.", "sys");
  }

  log(message, type = "sys") {
    const logObj = { time: new Date().toLocaleTimeString(), text: message, type };
    this.systemLogs.push(logObj);
    const event = new CustomEvent('blockchain-log', { detail: logObj });
    window.dispatchEvent(event);
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  getBalanceOfAddress(address) {
    let balance = 0;
    for (const block of this.chain) {
      for (const trans of block.transactions) {
        if (trans.fromAddress === address) {
          balance -= trans.amount + trans.gas;
        }
        if (trans.toAddress === address) {
          balance += trans.amount;
        }
      }
    }
    return balance;
  }

  async addTransaction(transaction) {
    if (!transaction.fromAddress || !transaction.toAddress) {
      throw new Error('Transaction must include from and to address');
    }

    const isValid = await transaction.isValid();
    if (!isValid) {
      throw new Error('Cannot add invalid transaction to chain (cryptographic validation failed)');
    }

    if (transaction.amount <= 0) {
      throw new Error('Transaction amount must be greater than 0');
    }

    const balance = this.getBalanceOfAddress(transaction.fromAddress);
    if (balance < (transaction.amount + transaction.gas)) {
      throw new Error('Insufficient balance to cover transaction and gas');
    }

    this.pendingTransactions.push(transaction);
    
    const sigType = transaction.pqcEnabled ? "ECDSA+WOTS+" : "ECDSA";
    this.log(`Pending Tx added (${sigType}): ${transaction.fromAddress.slice(0, 10)}... -> ${transaction.toAddress.slice(0,10)}... [${transaction.amount} AEGIS]`, "tx");
  }

  async minePendingTransactions(miningRewardAddress, onProgress) {
    this.log(`Starting Proof-of-Work block mining... (Difficulty: ${this.difficulty})`, "sys");
    
    const rewardTx = new Transaction('SYSTEM-MINT', miningRewardAddress, this.miningReward, 0, 0);
    const txsToMine = [rewardTx, ...this.pendingTransactions];
    
    const block = new Block(Date.now(), txsToMine, this.getLatestBlock().hash);
    await block.mineBlock(this.difficulty, onProgress);
    
    this.chain.push(block);
    this.log(`Block #${this.chain.length - 1} mined successfully! Hash: ${block.hash.slice(0, 15)}...`, "sec");
    
    for (const tx of this.pendingTransactions) {
      await this.executeSmartContract(tx);
    }
    
    this.pendingTransactions = [];
  }

  async executeSmartContract(tx) {
    if (tx.toAddress === '0xStakingContract') {
      const sender = tx.fromAddress;
      const amount = tx.amount;
      
      if (!this.contractsState.staking.stakes[sender]) {
        this.contractsState.staking.stakes[sender] = 0;
      }
      this.contractsState.staking.stakes[sender] += amount;
      this.contractsState.staking.totalStaked += amount;
      
      this.log(`[Smart Contract: Staking] ${sender.slice(0, 10)}... staked ${amount} AEGIS`, "sec");
    }
    
    if (tx.toAddress === '0xMultiSigVaultContract') {
      const sender = tx.fromAddress;
      const amount = tx.amount;
      
      if (!this.contractsState.multisig.owners.includes(sender)) {
        this.contractsState.multisig.owners.push(sender);
      }
      
      this.log(`[Smart Contract: MultiSig] Deposit of ${amount} AEGIS made by owner ${sender.slice(0,10)}...`, "sec");
    }

    if (tx.toAddress === '0xYieldOptimizerContract') {
      const sender = tx.fromAddress;
      const amount = tx.amount;
      
      this.contractsState.yieldOptimizer.totalValueLocked += amount;
      this.log(`[Smart Contract: YieldOptimizer] Deposited ${amount} AEGIS. Active AI balancing enabled.`, "sec");
    }
  }

  updateYieldOptimizerAllocations(safe, moderate, aggressive) {
    this.contractsState.yieldOptimizer.poolAllocation = { safe, moderate, aggressive };
    this.log(`[Smart Contract: YieldOptimizer] Reallocated assets: Safe ${safe}%, Moderate ${moderate}%, Aggressive ${aggressive}%`, "sys");
  }

  async isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      const currentHash = await currentBlock.calculateHash();
      if (currentBlock.hash !== currentHash) {
        return false;
      }

      if (currentBlock.previousHash !== previousBlock.hash) {
        return false;
      }
    }
    return true;
  }
}
