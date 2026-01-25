// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Unsafe Delegatecall
pragma solidity ^0.8.18;

/*
Name: Unsafe Delegatecall Vulnerability

Description:
The Proxy Contract Owner Manipulation Vulnerability is a flaw that allows an attacker
to manipulate the owner of the Proxy contract. The vulnerability arises due to the use
of delegatecall in the fallback function. delegatecall allows an attacker to invoke
the pwn() function from the Delegate contract within the context of the Proxy contract,
thereby changing the value of the owner state variable.

Mitigation:
Avoid using delegatecall unless explicitly required, and ensure that the delegatecall
is used securely with validated and sanitized inputs.
*/

contract Proxy {
    address public owner = address(0xdeadbeef); // slot0
    Delegate delegate;

    constructor(address _delegateAddress) {
        delegate = Delegate(_delegateAddress);
    }

    // VULNERABILITY: Unprotected delegatecall in fallback
    fallback() external {
        (bool suc, ) = address(delegate).delegatecall(msg.data);
        require(suc, "Delegatecall failed");
    }
}

contract Delegate {
    address public owner; // slot0

    function pwn() public {
        owner = msg.sender;
    }
}
