// SPDX-License-Identifier: MIT
// Vulnerable: Missing access control on critical functions
// Source: Common audit finding pattern

pragma solidity ^0.8.18;

contract MissingAccessControl {
    address public owner;
    mapping(address => uint256) public balances;
    bool public paused;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        require(!paused, "Contract is paused");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 _amount) public {
        require(!paused, "Contract is paused");
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        balances[msg.sender] -= _amount;
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, _amount);
    }

    // VULNERABLE: Missing access control - anyone can change owner
    function setOwner(address _newOwner) public {
        owner = _newOwner;
    }

    // VULNERABLE: Missing access control - anyone can pause
    function setPaused(bool _paused) public {
        paused = _paused;
    }

    // VULNERABLE: Missing access control - anyone can drain funds
    function emergencyWithdraw() public {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
}
