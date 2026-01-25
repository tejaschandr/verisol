// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Improper Access Control
pragma solidity ^0.8.18;

/*
Name: Improper Access Control Vulnerability

Description:
The default visibility of functions is Public. If there is an unsafe visibility setting,
the attacker can directly call sensitive functions. The changeOwner function lacks
access control and can be called by anyone.

Mitigation:
Use access control modifiers like onlyOwner to restrict sensitive functions.
*/

contract OwnerGame {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABILITY: Missing access control - should be onlyOwner
    function changeOwner(address _new) public {
        owner = _new;
    }
}
