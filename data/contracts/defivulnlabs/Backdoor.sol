// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Hidden Backdoor in Contract
pragma solidity ^0.8.18;

/*
Name: Hidden Backdoor in Contract

Description:
The LotteryGame contract has a hidden backdoor that allows the admin to set the winner
using assembly-level storage access. The modifier appears to check for randomness,
but actually lets the admin directly write to storage slot 1 (winner address).

This is a common rug pull pattern where the admin can drain prizes.

Mitigation:
Audit contracts for assembly usage. Avoid inline assembly in critical functions.
Use transparent access control patterns.
*/

contract LotteryGame {
    uint256 public prize = 1000;
    address public winner;
    address public admin = msg.sender;

    modifier safeCheck() {
        if (msg.sender == referee()) {
            _;
        } else {
            getkWinner();
        }
    }

    // VULNERABILITY: Hidden admin check via assembly
    function referee() internal view returns (address user) {
        assembly {
            // Load admin value from slot 2
            user := sload(2)
        }
    }

    // VULNERABILITY: Admin can directly set winner via assembly
    function pickWinner(address random) public safeCheck {
        assembly {
            // Backdoor: directly write to slot 1 (winner)
            sstore(1, random)
        }
    }

    function getkWinner() public view returns (address) {
        return winner;
    }
}
