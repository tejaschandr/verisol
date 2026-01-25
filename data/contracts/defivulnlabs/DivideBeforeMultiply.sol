// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Divide Before Multiply
pragma solidity ^0.8.18;

/*
Name: Precision Issues - Divide Before Multiply

Description:
Dividing before multiplying loses precision due to integer truncation.
If price/100 = 0 (for prices < 100), the entire calculation becomes 0.

Mitigation:
Always multiply before dividing.
*/

contract Miscalculation {
    // VULNERABILITY: Divides first, loses precision
    function price(uint256 _price, uint256 discount) public pure returns (uint256) {
        return (_price / 100) * discount; // wrong: 80/100 = 0, 0*90 = 0
    }
}

contract Calculation {
    // Correct: multiply first
    function price(uint256 _price, uint256 discount) public pure returns (uint256) {
        return (_price * discount) / 100; // correct: 80*90 = 7200, 7200/100 = 72
    }
}
