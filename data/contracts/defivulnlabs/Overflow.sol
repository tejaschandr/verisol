// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Integer Overflow (pre-0.8)
pragma solidity ^0.7.6;
// This needs to be older version of Solidity - 0.8.0+ has built-in overflow checks

/*
Name: Integer Overflow

Description:
The TimeLock has a flaw where an attacker can prematurely withdraw their deposited funds.
The vulnerability arises due to an overflow in the increaseLockTime function,
which manipulates the lock time to wrap around to 0.

Mitigation:
Use SafeMath library or Solidity >= 0.8 which has built-in overflow protection.
*/

contract TimeLock {
    mapping(address => uint) public balances;
    mapping(address => uint) public lockTime;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        lockTime[msg.sender] = block.timestamp + 1 weeks;
    }

    // VULNERABILITY: Can overflow lockTime to bypass time lock
    function increaseLockTime(uint _secondsToIncrease) public {
        lockTime[msg.sender] += _secondsToIncrease;
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
