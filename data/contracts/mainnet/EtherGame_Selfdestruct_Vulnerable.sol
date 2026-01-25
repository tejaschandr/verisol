// SPDX-License-Identifier: MIT
// Source: DeFiVulnLabs - Self-Destruct DoS Example
// Vulnerability: Contract relies on balance for logic, can be manipulated via selfdestruct

pragma solidity ^0.8.18;

contract EtherGame {
    uint public constant targetAmount = 7 ether;
    address public winner;

    // VULNERABLE: Relies on address(this).balance for game logic
    // An attacker can force-send ETH via selfdestruct, breaking the game
    function deposit() public payable {
        require(msg.value == 1 ether, "You can only send 1 Ether");

        uint balance = address(this).balance;
        require(balance <= targetAmount, "Game is over");

        if (balance == targetAmount) {
            winner = msg.sender;
        }
    }

    function claimReward() public {
        require(msg.sender == winner, "Not winner");

        (bool sent, ) = msg.sender.call{value: address(this).balance}("");
        require(sent, "Failed to send Ether");
    }
}
