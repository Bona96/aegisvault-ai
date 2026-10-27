/**
 * AegisVault AI Agent Engine
 * Operates client-side security audits, AI yield simulations, and security chatbot responses.
 */

// Rules for Solidity smart contract static analysis
const AUDIT_RULES = [
  {
    id: "VULN-REENTRANCY",
    name: "Potential Reentrancy Vulnerability",
    severity: "critical",
    pattern: /\.call\s*\{.*value:/i,
    check: (lines, index) => {
      // Look for calls that send ether before state updates
      const line = lines[index];
      // Check if subsequent lines have balance updates or updates to state variables
      let stateUpdateAfterCall = false;
      for (let i = index + 1; i < Math.min(lines.length, index + 10); i++) {
        if (lines[i].includes('balances[') || lines[i].includes('balanceOf[') || lines[i].includes('staked[') || lines[i].includes(' = 0') || lines[i].includes(' -= ')) {
          stateUpdateAfterCall = true;
          break;
        }
      }
      return stateUpdateAfterCall;
    },
    description: "External call transfers value before updating local state variables. Attackers could re-enter the contract and drain funds.",
    fix: "Implement the Checks-Effects-Interactions pattern: update state balances BEFORE making the external call, or use OpenZeppelin's ReentrancyGuard."
  },
  {
    id: "VULN-TX-ORIGIN",
    name: "Insecure tx.origin Authorization",
    severity: "critical",
    pattern: /tx\.origin/g,
    check: (lines, index) => lines[index].includes('tx.origin'),
    description: "Using tx.origin for authorization makes the contract vulnerable to phishing attacks (attacks via malicious intermediary contracts).",
    fix: "Replace tx.origin with msg.sender for sender verification."
  },
  {
    id: "VULN-OVERFLOW",
    name: "Legacy Integer Overflow Risk",
    severity: "warning",
    pattern: /pragma solidity [^0]/i,
    check: (lines, index) => {
      const line = lines[index];
      const match = line.match(/pragma solidity\s+([^;]+)/);
      if (match) {
        const verStr = match[1].trim();
        // Check if version is < 0.8.0
        if (verStr.includes('0.7.') || verStr.includes('0.6.') || verStr.includes('0.5.') || verStr.includes('^0.7.') || verStr.includes('^0.6.')) {
          // See if SafeMath is used
          const code = lines.join('\n');
          return !code.includes('SafeMath');
        }
      }
      return false;
    },
    description: "Solidity versions prior to 0.8.0 do not check for arithmetic overflow/underflow by default.",
    fix: "Upgrade to Solidity ^0.8.0, or import and use OpenZeppelin's SafeMath library for all arithmetic operations."
  },
  {
    id: "VULN-UNCHECKED-SEND",
    name: "Unchecked Return Value in Transfer",
    severity: "warning",
    pattern: /\.send\(|\.transfer\(/,
    check: (lines, index) => {
      const line = lines[index];
      return (line.includes('.send(') || line.includes('.transfer(')) && !line.includes('require(') && !line.includes('if (');
    },
    description: "The return values of low-level send or transfer functions are not verified. If the transfer fails, contract state execution continues.",
    fix: "Wrap low-level transfer/send in require statements (e.g. require(payable(to).send(amount), 'Transfer failed');) or use OpenZeppelin's SafeERC20."
  }
];

/**
 * AI Solidity Smart Contract Auditor
 */
export function auditSolidityCode(sourceCode) {
  const lines = sourceCode.split('\n');
  const vulnerabilities = [];

  lines.forEach((line, index) => {
    AUDIT_RULES.forEach(rule => {
      if (rule.pattern.test(line)) {
        if (rule.check(lines, index)) {
          vulnerabilities.push({
            id: rule.id,
            name: rule.name,
            severity: rule.severity,
            line: index + 1,
            codeSnippet: line.trim(),
            description: rule.description,
            fix: rule.fix
          });
        }
      }
    });
  });

  return {
    score: Math.max(0, 100 - (vulnerabilities.filter(v => v.severity === 'critical').length * 25) - (vulnerabilities.filter(v => v.severity === 'warning').length * 10)),
    vulnerabilities: vulnerabilities
  };
}

/**
 * AI Yield Optimizer Allocations Recommendations
 */
export function optimizeYieldPortfolio(riskProfile, marketCondition) {
  let safe = 100;
  let moderate = 0;
  let aggressive = 0;
  let yieldRate = 3.2; // Base yield rate percentage
  let reasoning = "";

  switch (riskProfile) {
    case 'low':
      if (marketCondition === 'volatile') {
        safe = 90; moderate = 10; aggressive = 0;
        yieldRate = 3.5;
        reasoning = "High market volatility detected. Sentry AI recommends locking 90% of assets in decentralized Treasury vaults (Zero-Trust) and 10% in blue-chip staking protocols to preserve principal.";
      } else {
        safe = 80; moderate = 20; aggressive = 0;
        yieldRate = 4.1;
        reasoning = "Stable market conditions. 80% safe government-equivalent staking pools, 20% index token yield pools. Zero-trust security parameters active.";
      }
      break;
    case 'medium':
      if (marketCondition === 'volatile') {
        safe = 60; moderate = 30; aggressive = 10;
        yieldRate = 5.8;
        reasoning = "Market is fluctuating. Sentry AI allocates 60% in secure vaults, 30% in liquidity provision for low-volatility pools, and 10% in automated hedging contracts.";
      } else {
        safe = 40; moderate = 50; aggressive = 10;
        yieldRate = 7.4;
        reasoning = "Healthy market momentum. 40% collateralized lending contracts, 50% automated arbitrage and liquidity pools, 10% high-yield multi-sig staking.";
      }
      break;
    case 'high':
      if (marketCondition === 'volatile') {
        safe = 30; moderate = 40; aggressive = 30;
        yieldRate = 9.2;
        reasoning = "Aggressive strategy in volatile market. 30% safety buffers, 40% stablecoin leveraged lending pools, 30% automated cross-dex arbitrage yield farming.";
      } else {
        safe = 10; moderate = 40; aggressive = 50;
        yieldRate = 12.8;
        reasoning = "Optimistic market environment. Portfolio reallocated: 50% to high-yield leveraged liquidity provision, 40% into collateral-backed synthetic loans, and 10% staking buffer.";
      }
      break;
  }

  return {
    safe,
    moderate,
    aggressive,
    yieldRate,
    reasoning
  };
}

/**
 * AI Chat Agent Responses
 */
const SENTRY_INTELLIGENCE_KNOWLEDGE = [
  {
    keywords: ["hello", "hi", "who are you", "sentry"],
    response: "Hello! I am Sentry AI, your zero-trust blockchain cybersecurity assistant. I can audit smart contracts, analyze security profiles, assist in key derivation setups, and optimize decentralized yields safely. How can I help you secure your digital assets today?"
  },
  {
    keywords: ["zero-trust", "zero trust", "architecture"],
    response: "AegisVault enforces **Zero-Trust Architecture** at the client layer. This means:\n1. We trust NO server: private keys are derived locally using Web Crypto PBKDF2 with 100k rounds.\n2. Cryptographic transaction payloads are signed locally. The network only verifies signatures, never handling keys.\n3. Smart contracts are verified by me (AI) before you authorize interactions."
  },
  {
    keywords: ["cryptography", "web crypto", "private key", "seed"],
    response: "We utilize the **Web Crypto API** (native and open-source) in your browser. All private keys are stored in-memory (or encrypted via 256-bit AES-GCM on LocalStorage). The master password generates key derivation functions locally. If the password is lost, we cannot recover it because we store ZERO records on our servers."
  },
  {
    keywords: ["zkp", "zero knowledge", "proof"],
    response: "Zero-Knowledge Proofs (ZKPs) allow you to verify identity or statements (e.g. proof of ownership) without revealing the underlying secret. In our security panel, you can run a simulated Fiat-Shamir ZKP where you prove to a verifier that you know your wallet's master password using one-way hash challenges, keeping the password completely hidden."
  },
  {
    keywords: ["reentrancy", "vulnerability", "hack"],
    response: "Reentrancy occurs when a contract sends funds to an untrusted contract before updating its state (like user balances). The attacker contract recursively calls the withdrawal function before the balance is deducted, draining the vault. My Solidity Audit tab checks for this pattern and flags the exact lines of risk!"
  },
  {
    keywords: ["staking", "yield", "optimize"],
    response: "Staking lets you deposit native tokens into smart contracts to secure the network and earn interest. The AI Yield Optimizer evaluates risk parameters (Low, Med, High) alongside market volatility feeds to automatically split assets between conservative vaults and leveraged staking pools."
  }
];

export async function askSentryAI(query) {
  const normalized = query.toLowerCase();
  
  // Find match
  let matchedResponse = null;
  for (const entry of SENTRY_INTELLIGENCE_KNOWLEDGE) {
    if (entry.keywords.some(kw => normalized.includes(kw))) {
      matchedResponse = entry.response;
      break;
    }
  }

  if (!matchedResponse) {
    matchedResponse = "I understand you are interested in AegisVault AI. I can help audit Solidity contracts for reentrancy issues, configure client-side AES-GCM wallets, verify Zero-Knowledge Proofs, or reallocate assets through the Yield Optimizer. Could you specify your question, or ask about 'zero-trust security'?";
  }

  // Simulate typing delay
  await new Promise(resolve => setTimeout(resolve, 800));
  return matchedResponse;
}
