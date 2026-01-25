# Data

Test contracts for benchmarking and validation.

## Structure

```
contracts/
├── mainnet/       # 13 curated contracts (vulnerable + clean)
├── defivulnlabs/  # 24 real vulnerability patterns
├── realworld/     # Additional real-world examples
└── raw/           # 169 educational contracts (solidity-by-example.org)
```

## Mainnet Contracts

| Contract | Status | Vulnerability |
|----------|--------|---------------|
| EtherStore_Vulnerable.sol | Vulnerable | Reentrancy |
| Proxy_Delegatecall_Vulnerable.sol | Vulnerable | Delegatecall |
| Wallet_TxOrigin_Vulnerable.sol | Vulnerable | tx.origin |
| MissingAccessControl_Vulnerable.sol | Vulnerable | Access control |
| TimeLock_Overflow_Vulnerable.sol | Vulnerable | Integer overflow |
| UncheckedReturn_Vulnerable.sol | Vulnerable | Unchecked return |
| FlashLoan_Vulnerable.sol | Vulnerable | Oracle manipulation |
| EtherGame_Selfdestruct_Vulnerable.sol | Vulnerable | DoS |
| SimpleToken_Clean.sol | Clean | - |
| SecureVault_Clean.sol | Clean | - |
| SimpleStaking_Clean.sol | Clean | - |
| SimpleMultisig_Clean.sol | Clean | - |
| WETH9.sol | Clean | - |

## DeFiVulnLabs

24 contracts from [DeFiVulnLabs](https://github.com/SunWeb3Sec/DeFiVulnLabs) - real vulnerability patterns used in the wild.

## Usage

```bash
# Audit a vulnerable contract
verisol audit data/contracts/mainnet/EtherStore_Vulnerable.sol

# Audit a clean contract
verisol audit data/contracts/mainnet/SimpleToken_Clean.sol --quick
```
