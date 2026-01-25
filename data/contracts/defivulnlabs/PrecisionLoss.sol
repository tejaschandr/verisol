// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Precision Loss
pragma solidity ^0.8.18;

/*
Name: Precision Loss - Rounding Down to Zero

Description:
When the numerator is smaller than the denominator, the result rounds to zero.
This is especially problematic with tokens that have few decimals (like USDC/USDT with 6).

Mitigation:
1. Use libraries for proper rounding
2. Require result is not zero
3. Multiply before dividing
*/

contract SimplePool {
    uint public totalDebt;
    uint public lastAccrueInterestTime;
    uint public loanTokenBalance;

    constructor() {
        totalDebt = 10000e6;  // USDC has 6 decimals
        lastAccrueInterestTime = block.timestamp - 1;
        loanTokenBalance = 500e18;
    }

    // VULNERABILITY: Division can round to zero
    function getCurrentReward() public view returns (uint _reward) {
        uint _timeDelta = block.timestamp - lastAccrueInterestTime;

        if (_timeDelta == 0) return 0;

        // Problem: totalDebt * _timeDelta can be smaller than denominator
        // 10_000_000_000 * 1 / 31_536_000_000_000_000_000_000_000 = 0
        _reward = (totalDebt * _timeDelta) / (365 days * 1e18);
    }
}
