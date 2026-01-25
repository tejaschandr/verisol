// SPDX-License-Identifier: MIT
// Vulnerable: Unchecked return values and unsafe external calls
// Source: Common audit finding pattern

pragma solidity ^0.8.18;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract UncheckedReturn {
    address public owner;
    IERC20 public token;

    mapping(address => uint256) public deposits;

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    function deposit(uint256 _amount) public {
        // VULNERABLE: Return value not checked
        // Some tokens don't return true/false, or return false on failure
        token.transferFrom(msg.sender, address(this), _amount);
        deposits[msg.sender] += _amount;
    }

    function withdraw(uint256 _amount) public {
        require(deposits[msg.sender] >= _amount, "Insufficient balance");

        deposits[msg.sender] -= _amount;

        // VULNERABLE: Return value not checked
        token.transfer(msg.sender, _amount);
    }

    // VULNERABLE: Low-level call without success check
    function executeCall(address _target, bytes memory _data) public {
        require(msg.sender == owner, "Not owner");

        // VULNERABLE: Return value ignored
        _target.call(_data);
    }

    // VULNERABLE: Approve race condition + unchecked return
    function approveToken(address _spender, uint256 _amount) public {
        require(msg.sender == owner, "Not owner");
        token.approve(_spender, _amount);
    }
}
