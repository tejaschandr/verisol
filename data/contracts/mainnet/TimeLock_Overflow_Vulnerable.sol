// SPDX-License-Identifier: MIT
// Source: DeFiVulnLabs - Integer Overflow Example
// Vulnerability: Uses Solidity 0.7.6 without SafeMath, allows overflow attack
// Note: Updated to 0.8.x with unchecked block to demonstrate the pattern

pragma solidity ^0.8.18;

contract TimeLock {
    mapping(address => uint) public balances;
    mapping(address => uint) public lockTime;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        lockTime[msg.sender] = block.timestamp + 1 weeks;
    }

    // VULNERABLE: Can overflow lockTime using unchecked arithmetic
    // In real 0.7.x code, this would overflow naturally
    function increaseLockTime(uint _secondsToIncrease) public {
        unchecked {
            lockTime[msg.sender] += _secondsToIncrease;
        }
    }

    function withdraw() public {
        require(balances[msg.sender] > 0, "Insufficient funds");
        require(
            block.timestamp > lockTime[msg.sender],
            "Lock time not expired"
        );

        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");
    }
}
