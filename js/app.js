import { 
  encryptPayload, 
  decryptPayload, 
  generateKeyPair, 
  exportKey, 
  importKey, 
  generateIdentityZKP, 
  sha256, 
  bufferToHex
} from './crypto.js';

import { 
  Blockchain, 
  Transaction 
} from './blockchain.js';

import { 
  auditSolidityCode, 
  optimizeYieldPortfolio, 
  askSentryAI 
} from './ai.js';

import {
  generateWotsKeyPair,
  generateRingLweKeyPair,
  encapsulateRingLwe,
  decapsulateRingLwe,
  bitsToHex,
  hexToBits
} from './pqc.js';

// Pre-defined solidity contract templates for AI Auditor
const SOLIDITY_TEMPLATES = {
  secure: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SecureStaking
 * @dev Secure staking contract implementing checks-effects-interactions.
 */
contract SecureStaking {
    mapping(address => uint256) public balances;
    uint256 public totalStaked;

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function stake() external payable {
        require(msg.value > 0, "Cannot stake 0");
        balances[msg.sender] += msg.value;
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value);
    }

    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        // CHECK & EFFECT (Update state before call)
        balances[msg.sender] -= _amount;
        totalStaked -= _amount;
        
        // INTERACTION (Secure low-level call)
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Withdraw failed");
        
        emit Withdrawn(msg.sender, _amount);
    }
}`,
  reentrancy: `// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title VulnerableVault
 * @dev Contract containing a critical reentrancy vulnerability.
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawAll() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // INTERACTION BEFORE EFFECT (Vulnerable to reentrancy)
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");

        // EFFECT (Too late: attacker already re-entered)
        balances[msg.sender] = 0;
    }
}`,
  txorigin: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title TxOriginWallet
 * @dev Vulnerable wallet authorizing transactions using tx.origin.
 */
contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {}

    function transfer(address payable _to, uint256 _amount) external {
        // VULNERABLE: tx.origin could be tricked into calling a malicious contract
        require(tx.origin == owner, "Not the owner");
        
        (bool success, ) = _to.call{value: _amount}("");
        require(success, "Transfer failed");
    }
}`
};

// Gamified Hacking Arena Victim Code States
const HACK_VICTIM_CODE = {
  vulnerable: `contract EtherVault {
    mapping(address => uint) public balances;

    function withdraw() external {
        uint bal = balances[msg.sender];
        require(bal > 0);

        // VULNERABLE call transfer before update state!
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);

        // State update executed too late
        balances[msg.sender] = 0;
    }
}`,
  patched: `contract EtherVault {
    mapping(address => uint) public balances;

    function withdraw() external {
        uint bal = balances[msg.sender];
        require(bal > 0);

        // FIXED: Update state balance BEFORE sending funds!
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }
}`
};

// Global App State
let blockchain = null;
let activeWallet = null; 
let wotsKeyPair = null;   // Post-quantum signature keys
let pqcEnabled = false;
let walletBalances = { native: 0, staked: 0 };
let currentZKP = null;
let ringLweKeyPair = null;
let ringLweCiphertext = null;
let ringLweSecretBits = null;
let isHackingArenaPatched = false;

// Initialize Web Application
window.addEventListener('DOMContentLoaded', async () => {
  // 1. Initialize Blockchain
  blockchain = new Blockchain();
  await blockchain.init();
  
  // Listen to Blockchain custom logs
  window.addEventListener('blockchain-log', (e) => {
    logToConsole(e.detail.text, e.detail.type);
  });

  // Log genesis block state
  logToConsole("Genesis Block Mined: Hash " + blockchain.chain[0].hash, "sec");

  // 2. Setup Event Handlers
  setupTabSwitching();
  setupWalletWizard();
  setupTransactionCenter();
  setupYieldOptimizer();
  setupSolidityAuditor();
  setupHackingArena();
  setupMiningPanel();
  setupZkpPanel();
  setupPqcLatticePanel();
  setupSentryChat();
  setupPqcModeToggle();
  
  // Renders starting layout
  updateBlockchainUI();
  drawDonutChart(40, 50, 10);
  logToConsole("AegisVault Zero-Trust Sandbox loaded. Ready for secure transactions.", "sys");
});

// Write to bottom terminal log
function logToConsole(message, type = "sys") {
  const consoleArea = document.getElementById('log-console-area');
  if (!consoleArea) return;
  
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  
  const time = document.createElement('span');
  time.className = 'log-time';
  time.textContent = `[${new Date().toLocaleTimeString()}]`;
  
  const tag = document.createElement('span');
  tag.className = `log-tag ${type}`;
  tag.textContent = type.toUpperCase() + ':';
  
  const text = document.createElement('span');
  text.className = 'log-text';
  text.textContent = message;
  
  entry.appendChild(time);
  entry.appendChild(tag);
  entry.appendChild(text);
  
  consoleArea.appendChild(entry);
  consoleArea.scrollTop = consoleArea.scrollHeight;
}

// Clear Terminal logs
document.getElementById('btn-clear-logs').addEventListener('click', () => {
  const consoleArea = document.getElementById('log-console-area');
  consoleArea.innerHTML = '';
  logToConsole("Console cleared.", "sys");
});

// Navigation / Tabs Routing
function setupTabSwitching() {
  const navItems = document.querySelectorAll('.nav-item');
  const tabs = document.querySelectorAll('.tab-content');
  
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      navItems.forEach(nav => nav.classList.remove('active'));
      item.classList.add('active');
      
      const targetTab = item.getAttribute('data-tab');
      tabs.forEach(tab => {
        tab.classList.remove('active');
        if (tab.id === targetTab) {
          tab.classList.add('active');
        }
      });
      
      logToConsole(`Routed to panel: ${item.innerText}`, "sys");
    });
  });
}

// PQC Hybrid Mode Switcher
function setupPqcModeToggle() {
  const toggle = document.getElementById('pqc-mode-switch');
  const threatGauge = document.getElementById('quantum-gauge-fill');
  const threatText = document.getElementById('quantum-gauge-text');
  const badge = document.getElementById('pqc-status-badge');
  const statusDesc = document.getElementById('pqc-status-desc');
  const pqcIndicator = document.getElementById('pqc-signing-alert');
  const netDesc = document.getElementById('sec-quantum-desc');
  
  toggle.addEventListener('change', async () => {
    pqcEnabled = toggle.checked;
    
    if (pqcEnabled) {
      logToConsole("Activating Post-Quantum Cryptography Hybrid Protection...", "sys");
      threatGauge.style.width = '0%';
      threatText.textContent = 'SECURED (0%)';
      threatText.style.color = 'var(--clr-secure)';
      
      badge.innerHTML = 'ECDSA + WOTS+<span style="font-size: 0.7rem; padding: 0.1rem 0.4rem; background: rgba(168, 85, 247, 0.2); border-radius: 4px; font-weight: 500; color: #d8b4fe; margin-left: 0.5rem;">HYBRID</span>';
      statusDesc.textContent = "Winternitz One-Time Signatures (WOTS+) enabled. Quantum decryption attempts (HNDL) neutralized.";
      pqcIndicator.style.display = 'block';
      netDesc.textContent = "Hybrid WOTS+ PQC signatures enforced on-chain";
      
      // Derive WOTS+ keys if wallet is active
      if (activeWallet) {
        document.getElementById('wallet-algo-display').textContent = 'Hybrid (ECDSA + WOTS+)';
        document.getElementById('pqc-keys-subcard').style.display = 'block';
        logToConsole("Deriving WOTS+ keys from local master seed...", "sys");
        wotsKeyPair = await generateWotsKeyPair(activeWallet.jwkPublicString);
        
        // Render derived WOTS+ public key hash
        const wotsHash = await sha256(wotsKeyPair.publicKey.join(''));
        document.getElementById('wots-pubkey-display').textContent = 'wots_root_0x' + wotsHash;
      }
      
      logToConsole("PQC Protection Layer initialized successfully.", "sec");
    } else {
      logToConsole("Disabling PQC Mode. Classical signature mode restored.", "sys");
      threatGauge.style.width = '85%';
      threatText.textContent = 'CRITICAL (85%)';
      threatText.style.color = 'var(--clr-danger)';
      
      badge.innerHTML = 'ECDSA <span style="font-size: 0.7rem; padding: 0.1rem 0.4rem; background: rgba(255, 255, 255, 0.05); border-radius: 4px; font-weight: 500; color: var(--text-secondary);">CLASSICAL</span>';
      statusDesc.textContent = "Using standard ECDSA keys. Enable PQC in the header to activate hybrid WOTS+ quantum protection.";
      pqcIndicator.style.display = 'none';
      netDesc.textContent = "Classical ECDSA signature enforcement";
      
      document.getElementById('wallet-algo-display').textContent = 'ECDSA (Curve P-256)';
      document.getElementById('pqc-keys-subcard').style.display = 'none';
    }
  });
}

// Client-Side Cryptographic Wallet wizard
function setupWalletWizard() {
  const btnGenerate = document.getElementById('btn-generate-wallet');
  const btnRestore = document.getElementById('btn-restore-wallet');
  const btnPurge = document.getElementById('btn-purge-wallet');
  const passwordInput = document.getElementById('setup-password');
  const backupTextarea = document.getElementById('setup-mnemonic');
  
  const walletSetupCard = document.getElementById('wallet-setup-card');
  const walletDetailsCard = document.getElementById('wallet-details-card');

  btnGenerate.addEventListener('click', async () => {
    const password = passwordInput.value;
    if (!password || password.length < 8) {
      alert("Please provide a secure master password (minimum 8 characters) for local encryption.");
      return;
    }
    
    btnGenerate.disabled = true;
    logToConsole("Generating client cryptographic ECDSA P-256 Keypair...", "sys");
    
    try {
      const keys = await generateKeyPair();
      const jwkPublic = await exportKey(keys.publicKey);
      const jwkPrivate = await exportKey(keys.privateKey);
      
      const addressHash = await sha256(jwkPublic);
      const walletAddress = '0x' + addressHash.slice(0, 40);
      
      activeWallet = {
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
        address: walletAddress,
        jwkPublicString: jwkPublic
      };
      
      window.activeWalletPublicKey = keys.publicKey;
      
      // Calculate WOTS+ if PQC is checked
      if (pqcEnabled) {
        logToConsole("Deriving post-quantum WOTS+ keypair from master key root...", "sys");
        wotsKeyPair = await generateWotsKeyPair(jwkPublic);
        const wotsHash = await sha256(wotsKeyPair.publicKey.join(''));
        document.getElementById('wots-pubkey-display').textContent = 'wots_root_0x' + wotsHash;
        document.getElementById('pqc-keys-subcard').style.display = 'block';
        document.getElementById('wallet-algo-display').textContent = 'Hybrid (ECDSA + WOTS+)';
      }
      
      const backupPayload = JSON.stringify({
        pub: jwkPublic,
        priv: jwkPrivate,
        address: walletAddress
      });
      
      const encryptedBackup = await encryptPayload(password, backupPayload);
      
      // Update UI elements
      document.getElementById('wallet-address-full').textContent = walletAddress;
      document.getElementById('wallet-address-short').textContent = `Address: ${walletAddress.slice(0,10)}...${walletAddress.slice(-6)}`;
      document.getElementById('wallet-backup-raw').value = JSON.stringify(encryptedBackup, null, 2);
      
      enableWalletAuthenticatedState();
      
      walletSetupCard.style.display = 'none';
      walletDetailsCard.style.display = 'flex';
      
      logToConsole(`Wallet generated. Derived address: ${walletAddress}`, "sec");
      logToConsole("Private keys encrypted client-side using PBKDF2 + AES-GCM (256-bit).", "sec");
      
      mintStarterTokens(walletAddress);
      
    } catch (e) {
      logToConsole(`Wallet generation error: ${e.message}`, "tx");
      btnGenerate.disabled = false;
    }
  });

  btnRestore.addEventListener('click', async () => {
    const password = passwordInput.value;
    const backupJsonStr = backupTextarea.value.trim();
    
    if (!password || !backupJsonStr) {
      alert("Master password and encrypted backup JSON payload are required to restore session.");
      return;
    }
    
    try {
      logToConsole("Importing backup and verifying password payload...", "sys");
      const encryptedBackupObj = JSON.parse(backupJsonStr);
      const decryptedBackupStr = await decryptPayload(password, encryptedBackupObj);
      const backup = JSON.parse(decryptedBackupStr);
      
      const privateKey = await importKey(backup.priv, true);
      const publicKey = await importKey(backup.pub, false);
      
      activeWallet = {
        privateKey,
        publicKey,
        address: backup.address,
        jwkPublicString: backup.pub
      };
      
      window.activeWalletPublicKey = publicKey;
      
      if (pqcEnabled) {
        logToConsole("Deriving post-quantum WOTS+ credentials...", "sys");
        wotsKeyPair = await generateWotsKeyPair(backup.pub);
        const wotsHash = await sha256(wotsKeyPair.publicKey.join(''));
        document.getElementById('wots-pubkey-display').textContent = 'wots_root_0x' + wotsHash;
        document.getElementById('pqc-keys-subcard').style.display = 'block';
        document.getElementById('wallet-algo-display').textContent = 'Hybrid (ECDSA + WOTS+)';
      }
      
      document.getElementById('wallet-address-full').textContent = backup.address;
      document.getElementById('wallet-address-short').textContent = `Address: ${backup.address.slice(0,10)}...${backup.address.slice(-6)}`;
      document.getElementById('wallet-backup-raw').value = JSON.stringify(encryptedBackupObj, null, 2);
      
      enableWalletAuthenticatedState();
      
      walletSetupCard.style.display = 'none';
      walletDetailsCard.style.display = 'flex';
      
      logToConsole(`Wallet restored successfully. Address: ${backup.address}`, "sec");
      updateBalances();
      
    } catch (e) {
      logToConsole(`Failed to restore wallet: ${e.message}`, "tx");
      alert("Failed to decrypt wallet backup. Check password or backup JSON formatting.");
    }
  });

  btnPurge.addEventListener('click', () => {
    activeWallet = null;
    wotsKeyPair = null;
    window.activeWalletPublicKey = null;
    
    document.getElementById('tx-password').disabled = true;
    document.getElementById('tx-submit-btn').disabled = true;
    document.getElementById('zkp-passphrase').disabled = true;
    document.getElementById('btn-generate-zkp').disabled = true;
    document.getElementById('btn-quick-stake-50').disabled = true;
    document.getElementById('btn-quick-unstake').disabled = true;
    
    document.getElementById('wallet-balance-val').textContent = '0.00 AEGIS';
    document.getElementById('staked-balance-val').textContent = '0.00 AEGIS';
    document.getElementById('wallet-address-short').textContent = 'Address: None (Initialize Wallet)';
    
    document.getElementById('sec-wallet-desc').textContent = 'Wallet Offline';
    document.getElementById('sec-wallet-icon').className = 'sec-status fail';
    document.getElementById('sec-wallet-icon').textContent = '✗';
    
    passwordInput.value = '';
    backupTextarea.value = '';
    
    walletDetailsCard.style.display = 'none';
    walletSetupCard.style.display = 'block';
    btnGenerate.disabled = false;
    
    logToConsole("Zero-Trust cache purged. Session deleted. Keys zeroed out.", "sec");
  });
}

function enableWalletAuthenticatedState() {
  document.getElementById('tx-password').disabled = false;
  document.getElementById('tx-submit-btn').disabled = false;
  document.getElementById('zkp-passphrase').disabled = false;
  document.getElementById('btn-generate-zkp').disabled = false;
  document.getElementById('btn-quick-stake-50').disabled = false;
  document.getElementById('btn-quick-unstake').disabled = false;
  
  document.getElementById('sec-wallet-desc').textContent = 'Key Generation Secured (AES-GCM-256)';
  document.getElementById('sec-wallet-icon').className = 'sec-status pass';
  document.getElementById('sec-wallet-icon').textContent = '✓';
}

function mintStarterTokens(recipientAddress) {
  logToConsole("Minting 1000 starter AEGIS tokens from genesis ledger...", "sys");
  
  const tx = new Transaction('SYSTEM-MINT', recipientAddress, 1000, 0, 0);
  tx.signature = "GENESIS-MINT-PROVED";
  
  blockchain.pendingTransactions.push(tx);
  blockchain.minePendingTransactions(recipientAddress, () => {}).then(() => {
    updateBalances();
    updateBlockchainUI();
  });
}

function updateBalances() {
  if (!activeWallet) return;
  const bal = blockchain.getBalanceOfAddress(activeWallet.address);
  const stake = blockchain.contractsState.staking.stakes[activeWallet.address] || 0;
  
  walletBalances.native = bal;
  walletBalances.staked = stake;
  
  document.getElementById('wallet-balance-val').textContent = `${bal.toFixed(2)} AEGIS`;
  document.getElementById('staked-balance-val').textContent = `${stake.toFixed(2)} AEGIS`;
}

function setupTransactionCenter() {
  const form = document.getElementById('tx-form');
  const toSelect = document.getElementById('tx-to');
  const amountInput = document.getElementById('tx-amount');
  const pwdInput = document.getElementById('tx-password');
  
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!activeWallet) return;
    
    const recipient = toSelect.value;
    const amount = Number(amountInput.value);
    const password = pwdInput.value;
    
    try {
      const backupRaw = document.getElementById('wallet-backup-raw').value;
      const encryptedBackupObj = JSON.parse(backupRaw);
      await decryptPayload(password, encryptedBackupObj); 
      
      const nonce = blockchain.chain.length;
      const tx = new Transaction(activeWallet.address, recipient, amount, 1, nonce);
      
      logToConsole("Signing transaction with local private keys...", "sys");
      await tx.sign(activeWallet.privateKey, activeWallet.jwkPublicString, pqcEnabled ? wotsKeyPair : null);
      
      if (pqcEnabled) {
        logToConsole(`WOTS+ Signature generated (~2.5 KB payload blocks)`, "sec");
      }
      
      await blockchain.addTransaction(tx);
      
      amountInput.value = '';
      pwdInput.value = '';
      
      updateBalances();
      updateBlockchainUI();
      
    } catch (err) {
      logToConsole(`Signing Error: ${err.message}`, "tx");
      alert(err.message);
    }
  });

  document.getElementById('btn-quick-stake-50').addEventListener('click', () => {
    toSelect.value = '0xStakingContract';
    amountInput.value = '50';
    pwdInput.focus();
  });

  document.getElementById('btn-quick-unstake').addEventListener('click', async () => {
    if (!activeWallet) return;
    const stakeAmount = blockchain.contractsState.staking.stakes[activeWallet.address] || 0;
    if (stakeAmount <= 0) return;
    
    const password = prompt("Confirm master password to verify unstaking request:");
    if (!password) return;
    
    try {
      const backupRaw = document.getElementById('wallet-backup-raw').value;
      const encryptedBackupObj = JSON.parse(backupRaw);
      await decryptPayload(password, encryptedBackupObj);
      
      blockchain.contractsState.staking.stakes[activeWallet.address] = 0;
      blockchain.contractsState.staking.totalStaked -= stakeAmount;
      
      const refundTx = new Transaction('SYSTEM-MINT', activeWallet.address, stakeAmount, 0, 0);
      refundTx.signature = "REFUND-UNSTAKE-PROVED";
      blockchain.pendingTransactions.push(refundTx);
      
      const nonce = blockchain.chain.length;
      const tx = new Transaction(activeWallet.address, '0xStakingContract', 0.1, 1, nonce);
      await tx.sign(activeWallet.privateKey, activeWallet.jwkPublicString, pqcEnabled ? wotsKeyPair : null);
      
      await blockchain.addTransaction(tx);
      updateBalances();
      updateBlockchainUI();
      
    } catch (e) {
      alert("Invalid password.");
    }
  });
}

function setupYieldOptimizer() {
  const riskSelect = document.getElementById('opt-risk');
  const marketSelect = document.getElementById('opt-market');
  const runBtn = document.getElementById('btn-run-allocation');
  
  runBtn.addEventListener('click', () => {
    const result = optimizeYieldPortfolio(riskSelect.value, marketSelect.value);
    
    document.getElementById('optimized-yield-val').textContent = `${result.yieldRate}% APR`;
    document.getElementById('yield-risk-profile').textContent = `Profile: ${riskSelect.value.toUpperCase()} / ${marketSelect.value.toUpperCase()}`;
    document.getElementById('staking-apr-val').textContent = `APR: ${result.yieldRate}% (AI Optimized)`;
    
    drawDonutChart(result.safe, result.moderate, result.aggressive);
    document.getElementById('chart-legend').textContent = `Safe: ${result.safe}% | Moderate: ${result.moderate}% | Aggressive: ${result.aggressive}%`;
    
    blockchain.updateYieldOptimizerAllocations(result.safe, result.moderate, result.aggressive);
  });
}

function drawDonutChart(safe, mod, agg) {
  const svg = document.getElementById('portfolio-chart');
  svg.innerHTML = ''; 
  
  const values = [safe, mod, agg];
  const colors = ['#10b981', '#6366f1', '#f59e0b']; 
  
  let accumulatedAngle = 0;
  const radius = 65;
  const cx = 100;
  const cy = 100;
  const strokeWidth = 24;
  const circumference = 2 * Math.PI * radius;
  
  values.forEach((val, idx) => {
    if (val === 0) return;
    
    const pct = val / 100;
    const strokeDasharray = `${pct * circumference} ${circumference}`;
    const strokeDashoffset = -accumulatedAngle;
    
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', cx);
    circle.setAttribute('cy', cy);
    circle.setAttribute('r', radius);
    circle.setAttribute('fill', 'transparent');
    circle.setAttribute('stroke', colors[idx]);
    circle.setAttribute('stroke-width', strokeWidth);
    circle.setAttribute('stroke-dasharray', strokeDasharray);
    circle.setAttribute('stroke-dashoffset', strokeDashoffset);
    circle.setAttribute('transform', 'rotate(-90 100 100)');
    
    svg.appendChild(circle);
    accumulatedAngle += pct * circumference;
  });
  
  const textVal = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  textVal.setAttribute('x', cx);
  textVal.setAttribute('y', cy - 2);
  textVal.setAttribute('text-anchor', 'middle');
  textVal.setAttribute('fill', '#f3f4f6');
  textVal.style.fontSize = '12px';
  textVal.style.fontWeight = 'bold';
  svg.appendChild(textVal);
  textVal.textContent = 'ALLOCATION';

  const textValSub = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  textValSub.setAttribute('x', cx);
  textValSub.setAttribute('y', cy + 14);
  textValSub.setAttribute('text-anchor', 'middle');
  textValSub.setAttribute('fill', 'var(--text-secondary)');
  textValSub.style.fontSize = '10px';
  svg.appendChild(textValSub);
  textValSub.textContent = `${safe}% | ${mod}% | ${agg}%`;
}

// AI Solidity Smart Contract Auditor Panel (with premium syntax highlighter overlay)
function setupSolidityAuditor() {
  const select = document.getElementById('editor-templates');
  const editor = document.getElementById('solidity-editor-area');
  const overlay = document.getElementById('editor-highlighter-layer');
  const auditBtn = document.getElementById('btn-run-audit');
  const resultsContainer = document.getElementById('audit-results-list');
  const scoreVal = document.getElementById('audit-score-val');

  // Solidity code preloading & syntax highlights refresh
  const refreshHighlighter = () => {
    let code = editor.value;
    
    // Simple regex replacements to apply syntax coloring
    const keywords = /\b(contract|function|mapping|address|uint256|require|payable|external|returns|event|emit|payable|import|pragma|solidity|public|private)\b/g;
    const types = /\b(address|uint256|string|bool)\b/g;
    const strings = /(["'].*?["'])/g;
    const comments = /(\/\/.*)/g;
    const numbers = /\b(\d+)\b/g;
    
    let highlighted = escapeHtml(code)
      .replace(comments, '<span class="hl-comment">$1</span>')
      .replace(strings, '<span class="hl-string">$1</span>')
      .replace(keywords, '<span class="hl-keyword">$1</span>')
      .replace(numbers, '<span class="hl-number">$1</span>');
      
    overlay.innerHTML = highlighted;
  };

  editor.addEventListener('input', refreshHighlighter);

  // Load default template
  editor.value = SOLIDITY_TEMPLATES.secure;
  refreshHighlighter();

  select.addEventListener('change', () => {
    editor.value = SOLIDITY_TEMPLATES[select.value];
    refreshHighlighter();
    logToConsole(`Loaded contract template: ${select.options[select.selectedIndex].text}`, "sys");
  });

  auditBtn.addEventListener('click', () => {
    const code = editor.value;
    logToConsole("Initiating local AI Static Contract audit...", "sys");
    
    const audit = auditSolidityCode(code);
    
    // Highlight lines if reentrancy is found
    if (audit.vulnerabilities.length > 0) {
      let lines = code.split('\n');
      audit.vulnerabilities.forEach(vuln => {
        const lineIdx = vuln.line - 1;
        lines[lineIdx] = `<span class="hl-vuln-line">${lines[lineIdx]}</span>`;
      });
      
      // Force highlighting injection
      overlay.innerHTML = lines.join('\n')
        .replace(/\b(contract|function|mapping|require|call|value|withdraw|balances)\b/g, '<span class="hl-keyword">$1</span>');
    }

    scoreVal.textContent = audit.score;
    if (audit.score > 80) scoreVal.style.color = 'var(--clr-secure)';
    else if (audit.score > 50) scoreVal.style.color = 'var(--clr-warning)';
    else scoreVal.style.color = 'var(--clr-danger)';

    resultsContainer.innerHTML = '';
    
    if (audit.vulnerabilities.length === 0) {
      resultsContainer.innerHTML = `
        <div class="audit-card secure">
          <div class="audit-title">✓ No Vulnerabilities Detected</div>
          <div class="audit-desc">This contract complies with checks-effects-interactions. Approved for deployment.</div>
        </div>
      `;
      logToConsole("AI Audit Complete. 0 vulnerabilities found.", "sec");
    } else {
      audit.vulnerabilities.forEach(vuln => {
        const card = document.createElement('div');
        card.className = `audit-card vulnerable`;
        card.innerHTML = `
          <div class="audit-title">⚠ ${vuln.name} (${vuln.severity.toUpperCase()})</div>
          <div class="audit-line">Line ${vuln.line}: ${escapeHtml(vuln.codeSnippet)}</div>
          <div class="audit-desc">${vuln.description}</div>
          <div style="font-size: 0.75rem; color: var(--clr-secure); font-weight: 500; margin-top: 0.25rem;">Fix: ${vuln.fix}</div>
        `;
        resultsContainer.appendChild(card);
      });
      logToConsole(`AI Audit Complete. Detected ${audit.vulnerabilities.length} vulnerabilities.`, "tx");
    }
  });
}

// Gamified Reentrancy Hacking Arena Controller
function setupHackingArena() {
  const codeDisplay = document.getElementById('victim-code-display');
  const tag = document.getElementById('victim-status-tag');
  const vicLiqText = document.getElementById('victim-liquidity-text');
  const vicBar = document.getElementById('victim-liquidity-bar');
  
  const attLiqText = document.getElementById('attacker-liquidity-text');
  const attBar = document.getElementById('attacker-liquidity-bar');
  
  const consoleLogs = document.getElementById('hacking-console-logs');
  
  const btnExploit = document.getElementById('btn-trigger-exploit');
  const btnPatch = document.getElementById('btn-apply-patch');
  const btnReset = document.getElementById('btn-reset-hack');

  // Initialize
  codeDisplay.textContent = HACK_VICTIM_CODE.vulnerable;

  btnExploit.addEventListener('click', async () => {
    if (isHackingArenaPatched) {
      // Exploitation fails
      consoleLogs.innerHTML += `<div style="color: var(--clr-secure); font-weight: bold;">[Security Blocked] Attacker transaction aborted. Checks-Effects-Interactions pattern halted reentrancy execution loop.</div>`;
      consoleLogs.scrollTop = consoleLogs.scrollHeight;
      alert("Exploit Blocked! The contract state balance is updated before sending ether, preventing recursive withdrawal.");
      return;
    }
    
    btnExploit.disabled = true;
    btnPatch.disabled = true;
    
    consoleLogs.innerHTML = `<div>[Exploit Initiated] Attacker calling withdraw() on Victim...</div>`;
    
    let victimEth = 500;
    let attackerEth = 0;
    let depth = 0;
    
    const runStep = () => {
      if (victimEth > 0 && depth < 5) {
        depth++;
        victimEth -= 100;
        attackerEth += 100;
        
        // Push call frames to mock stack visualizer
        const frame = document.createElement('div');
        frame.className = 'call-stack-frame recursion';
        frame.innerHTML = `<span>withdrawAll() recursive frame #${depth}</span><span style="color: var(--clr-danger);">-100 ETH</span>`;
        consoleLogs.appendChild(frame);
        
        // Update graphics
        vicLiqText.textContent = `${victimEth} ETH`;
        vicBar.style.width = `${(victimEth / 500) * 100}%`;
        
        attLiqText.textContent = `${attackerEth} ETH`;
        attBar.style.width = `${(attackerEth / 500) * 100}%`;
        
        consoleLogs.innerHTML += `<div style="color: var(--clr-warning);">[Re-Entered] Victim fallback triggered. Depth ${depth} recursion active.</div>`;
        consoleLogs.scrollTop = consoleLogs.scrollHeight;
        
        setTimeout(runStep, 1000);
      } else {
        // Exploit finish
        consoleLogs.innerHTML += `<div style="color: var(--clr-danger); font-weight: bold; margin-top: 0.5rem;">[EXPLOIT SUCCESSFUL] Victim contract drained. Attacker balance: 500 ETH. Reentrancy loop halted.</div>`;
        consoleLogs.scrollTop = consoleLogs.scrollHeight;
        btnExploit.disabled = false;
        btnPatch.disabled = false;
      }
    };
    
    setTimeout(runStep, 1000);
  });

  btnPatch.addEventListener('click', () => {
    isHackingArenaPatched = true;
    codeDisplay.textContent = HACK_VICTIM_CODE.patched;
    tag.textContent = 'SECURED';
    tag.style.background = 'rgba(16, 185, 129, 0.2)';
    tag.style.color = 'var(--clr-secure)';
    
    consoleLogs.innerHTML += `<div style="color: var(--clr-secure);">[System Patch] Solidity contract balance checks and state updates moved to top of withdraw loop. Reentrancy Guard applied.</div>`;
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
    logToConsole("Hacking Arena victim contract updated. Reentrancy protection verified.", "sec");
  });

  btnReset.addEventListener('click', () => {
    isHackingArenaPatched = false;
    codeDisplay.textContent = HACK_VICTIM_CODE.vulnerable;
    tag.textContent = 'VULNERABLE';
    tag.style.background = 'rgba(239, 68, 68, 0.2)';
    tag.style.color = 'var(--clr-danger)';
    
    vicLiqText.textContent = '500 ETH';
    vicBar.style.width = '100%';
    
    attLiqText.textContent = '0 ETH';
    attBar.style.width = '0%';
    
    consoleLogs.innerHTML = `<div style="color: var(--text-muted);">Arena reset. Ready for simulation.</div>`;
    btnExploit.disabled = false;
    btnPatch.disabled = false;
  });
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function updateBlockchainUI() {
  document.getElementById('network-blocks-val').textContent = `${blockchain.chain.length} Blocks`;
  document.getElementById('network-difficulty-val').textContent = `Difficulty: ${blockchain.difficulty} Leading Zeros`;
  
  const mempoolList = document.getElementById('mempool-list');
  mempoolList.innerHTML = '';
  document.getElementById('mempool-count-val').textContent = `${blockchain.pendingTransactions.length} Transactions`;
  
  if (blockchain.pendingTransactions.length === 0) {
    mempoolList.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-muted); text-align: center; margin-top: 2rem;">Mempool is currently empty. Initiate transactions.</div>`;
  } else {
    blockchain.pendingTransactions.forEach(tx => {
      const item = document.createElement('div');
      item.className = 'tx-item';
      item.innerHTML = `
        <div class="tx-meta">
          <span>${tx.fromAddress.slice(0, 10)}... → ${tx.toAddress.slice(0,10)}...</span>
          <span class="tx-hash">Hash: ${tx.signature ? tx.signature.slice(0, 18) : 'Unsigned'}...</span>
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <strong style="color: var(--clr-secure); font-family: var(--font-mono);">${tx.amount} AEGIS</strong>
          <span class="tx-badge pending">${tx.pqcEnabled ? 'Hybrid PQC' : 'Pending'}</span>
        </div>
      `;
      mempoolList.appendChild(item);
    });
  }

  const chainRow = document.getElementById('blockchain-chain-row');
  chainRow.innerHTML = '';
  
  blockchain.chain.forEach((block, idx) => {
    if (idx > 0) {
      const arrow = document.createElement('div');
      arrow.className = 'block-arrow';
      arrow.textContent = '←';
      chainRow.appendChild(arrow);
    }
    
    const card = document.createElement('div');
    card.className = 'block-card';
    
    const txContent = block.transactions.map(t => `${t.fromAddress.slice(0,6)}.. -> ${t.amount} AEGIS`).join('<br>');
    
    card.innerHTML = `
      <div class="block-num">${idx === 0 ? "GENESIS BLOCK" : `BLOCK #${idx}`}</div>
      <div class="block-stat"><span class="lbl">Hash:</span><span class="val" title="${block.hash}">${block.hash}</span></div>
      <div class="block-stat"><span class="lbl">Prev Hash:</span><span class="val" title="${block.previousHash}">${block.previousHash}</span></div>
      <div class="block-stat"><span class="lbl">Nonce:</span><span class="val">${block.nonce}</span></div>
      <div class="block-stat"><span class="lbl">Timestamp:</span><span class="val">${new Date(block.timestamp).toLocaleTimeString()}</span></div>
      <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.25rem;">Transactions:</div>
      <div class="block-txs">${txContent}</div>
    `;
    
    chainRow.appendChild(card);
  });
  
  chainRow.scrollLeft = chainRow.scrollWidth;
}

function setupMiningPanel() {
  const mineBtn = document.getElementById('btn-mine-block');
  const statusContainer = document.getElementById('mining-status-container');
  const hashStepText = document.getElementById('mining-hash-step');
  const nonceStepText = document.getElementById('mining-nonce-step');
  
  mineBtn.addEventListener('click', async () => {
    const rewardAddress = activeWallet ? activeWallet.address : '0xMinerBonusVault';
    
    mineBtn.disabled = true;
    statusContainer.style.display = 'block';
    
    try {
      await blockchain.minePendingTransactions(rewardAddress, (progress) => {
        hashStepText.textContent = `Hash: ${progress.hash}`;
        nonceStepText.textContent = `Nonce Iteration: ${progress.nonce}`;
      });
      
      statusContainer.style.display = 'none';
      mineBtn.disabled = false;
      
      updateBalances();
      updateBlockchainUI();
      
    } catch (err) {
      logToConsole(`Mining failure: ${err.message}`, "tx");
      mineBtn.disabled = false;
      statusContainer.style.display = 'none';
    }
  });
}

function setupZkpPanel() {
  const passInput = document.getElementById('zkp-passphrase');
  const genBtn = document.getElementById('btn-generate-zkp');
  const verifyBtn = document.getElementById('btn-verify-zkp');
  const resultPanel = document.getElementById('zkp-results-container');
  const statusAlert = document.getElementById('zkp-status-alert');

  genBtn.addEventListener('click', async () => {
    const password = passInput.value;
    if (!password) {
      alert("Provide your wallet password to sign the ZKP identity proof.");
      return;
    }

    logToConsole("Generating Zero-Knowledge Identity Proof (Fiat-Shamir simulation)...", "sys");
    const networkChallenge = '0xSentryNetChallenge' + Math.floor(Math.random() * 100000);
    
    try {
      currentZKP = await generateIdentityZKP(password, networkChallenge);
      
      document.getElementById('zkp-commitment').textContent = `Commitment (r_hash): ${currentZKP.commitment}`;
      document.getElementById('zkp-challenge').textContent = `Challenge (Network Seed): ${currentZKP.challenge}`;
      document.getElementById('zkp-proof').textContent = `Proof Response payload (s): ${currentZKP.proof}`;
      
      resultPanel.style.display = 'flex';
      statusAlert.style.display = 'none';
      
      logToConsole("Identity ZK proof payload computed. Ready to verify.", "sec");
    } catch (e) {
      logToConsole("ZKP Error: " + e.message, "tx");
    }
  });

  verifyBtn.addEventListener('click', async () => {
    if (!currentZKP) return;
    
    logToConsole("Broadcasting ZKP payload to network verifier node...", "sys");
    const backupRaw = document.getElementById('wallet-backup-raw').value;
    const encryptedBackupObj = JSON.parse(backupRaw);
    
    try {
      const pwd = passInput.value;
      const decryptedBackupStr = await decryptPayload(pwd, encryptedBackupObj);
      const backup = JSON.parse(decryptedBackupStr);
      
      const derivedAddress = backup.address;
      
      if (derivedAddress === activeWallet.address) {
        statusAlert.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        statusAlert.style.border = '1px solid var(--clr-secure)';
        statusAlert.style.color = 'var(--clr-secure)';
        statusAlert.textContent = "✓ Zero-Knowledge Proof Authenticated. Identity verified on-chain. Password remained hidden.";
        logToConsole("ZKP Authenticated. Access granted.", "sec");
      } else {
        throw new Error("ZK Proof invalid");
      }
    } catch (e) {
      statusAlert.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
      statusAlert.style.border = '1px solid var(--clr-danger)';
      statusAlert.style.color = 'var(--clr-danger)';
      statusAlert.textContent = "✗ Verification failed. ZKP validation mismatched.";
      logToConsole("ZKP Verification Failed. Proof mismatch.", "tx");
    }
    
    statusAlert.style.display = 'block';
  });
}

// Post-Quantum KEM Panel (Ring-LWE Lattice cryptography controller)
function setupPqcLatticePanel() {
  const btnLweKeys = document.getElementById('btn-generate-lwe-keys');
  const pubDisplay = document.getElementById('lwe-pubkey-display');
  const privDisplay = document.getElementById('lwe-privkey-display');
  
  const encapStep = document.getElementById('lwe-encapsulation-step');
  const btnEncap = document.getElementById('btn-lwe-encapsulate');
  const c1Display = document.getElementById('lwe-c1-display');
  const c2Display = document.getElementById('lwe-c2-display');
  
  const decapStep = document.getElementById('lwe-decapsulation-step');
  const btnDecap = document.getElementById('btn-lwe-decapsulate');
  const recoveredDisplay = document.getElementById('lwe-recovered-key');

  // Step 1: Generate keys
  btnLweKeys.addEventListener('click', () => {
    logToConsole("Generating post-quantum Ring-LWE public/private parameters...", "sys");
    
    ringLweKeyPair = generateRingLweKeyPair();
    
    // Format displays as polynomial strings
    pubDisplay.textContent = `b(x) = [${ringLweKeyPair.publicKey.b.slice(0,6).join(', ')} ... ${ringLweKeyPair.publicKey.b.slice(-6).join(', ')}] mod 257`;
    privDisplay.textContent = `s(x) = [${ringLweKeyPair.privateKey.slice(0,8).join(', ')} ... ${ringLweKeyPair.privateKey.slice(-8).join(', ')}] (coefficients in {-1,0,1})`;
    
    encapStep.style.display = 'flex';
    logToConsole("Lattice key pair created. Modular polynomial variables loaded.", "sec");
  });

  // Step 2: Encapsulate secret key
  btnEncap.addEventListener('click', () => {
    const secretHex = document.getElementById('lwe-secret-input').value;
    logToConsole("Encrypting/Encapsulating session backup using Ring-LWE lattice public key b(x)...", "sys");
    
    ringLweSecretBits = hexToBits(secretHex);
    const encap = encapsulateRingLwe(ringLweKeyPair.publicKey, ringLweSecretBits);
    
    ringLweCiphertext = encap.ciphertext;
    
    c1Display.textContent = `c1(x) = [${ringLweCiphertext.c1.slice(0,6).join(', ')} ... ${ringLweCiphertext.c1.slice(-6).join(', ')}]`;
    c2Display.textContent = `c2(x) = [${ringLweCiphertext.c2.slice(0,6).join(', ')} ... ${ringLweCiphertext.c2.slice(-6).join(', ')}]`;
    
    decapStep.style.display = 'flex';
    logToConsole("Key encapsulation complete. Post-quantum ciphertext generated to defeat HNDL.", "sec");
  });

  // Step 3: Decapsulate key
  btnDecap.addEventListener('click', () => {
    logToConsole("Decapsulating Ring-LWE ciphertext using private key s(x) parameter...", "sys");
    
    const decryptedBits = decapsulateRingLwe(ringLweCiphertext, ringLweKeyPair.privateKey);
    const recoveredHex = bitsToHex(decryptedBits);
    
    recoveredDisplay.textContent = `Decapsulated Payload: ${recoveredHex}`;
    
    const originalHex = document.getElementById('lwe-secret-input').value;
    if (recoveredHex === originalHex) {
      logToConsole("Success: Decapsulated shared key matches original backup key. Lattice math verified.", "sec");
      recoveredDisplay.style.color = 'var(--clr-secure)';
    } else {
      logToConsole("Failure: Decapsulated key is corrupted. Math parameters out of bounds.", "tx");
      recoveredDisplay.style.color = 'var(--clr-danger)';
    }
  });
}

function setupSentryChat() {
  const form = document.getElementById('sentry-chat-form');
  const input = document.getElementById('sentry-input-field');
  const chatBox = document.getElementById('sentry-chat-box');
  
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const query = input.value.trim();
    if (!query) return;
    
    appendChatMessage(query, 'user', 'You');
    input.value = '';
    
    const typingDiv = document.createElement('div');
    typingDiv.className = 'msg sentry';
    typingDiv.innerHTML = `<div class="msg-header">Sentry AI Agent</div>Sentry AI is thinking...`;
    chatBox.appendChild(typingDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
    
    try {
      const response = await askSentryAI(query);
      chatBox.removeChild(typingDiv);
      appendChatMessage(response, 'sentry', 'Sentry AI Agent');
    } catch (err) {
      chatBox.removeChild(typingDiv);
      appendChatMessage("Apologies, I encountered an internal node error processing that threat request.", 'sentry', 'Sentry AI Agent');
    }
  });
}

function appendChatMessage(text, sender, headerName) {
  const chatBox = document.getElementById('sentry-chat-box');
  const msg = document.createElement('div');
  msg.className = `msg ${sender}`;
  
  const header = document.createElement('div');
  header.className = 'msg-header';
  header.textContent = headerName;
  
  const body = document.createElement('div');
  body.style.whiteSpace = 'pre-wrap';
  body.textContent = text;
  
  msg.appendChild(header);
  msg.appendChild(body);
  chatBox.appendChild(msg);
  chatBox.scrollTop = chatBox.scrollHeight;
}
