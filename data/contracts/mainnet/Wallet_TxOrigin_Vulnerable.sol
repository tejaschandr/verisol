// SPDX-License-Identifier: MIT
// Source: DeFiVulnLabs - tx.origin Phishing Example
// Vulnerability: Uses tx.origin for authentication, allowing phishing attacks

pragma solidity ^0.8.18;

contract Wallet {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    // VULNERABLE: Uses tx.origin instead of msg.sender
    // An attacker can trick the owner into calling a malicious contract
    // which then calls this function with owner's tx.origin
    function transfer(address payable _to, uint _amount) public {
        require(tx.origin == owner, "Not owner");
        (bool sent, ) = _to.call{value: _amount}("");
        require(sent, "Failed to send Ether");
    }
}
