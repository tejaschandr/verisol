// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Unsafe External Call
pragma solidity ^0.8.18;

/*
Name: Unsafe Call Vulnerability

Description:
The approveAndCallcode function allows an arbitrary call to be executed with
arbitrary data. This can lead to unexpected behavior, reentrancy attacks,
or unauthorized operations.

Mitigation:
Avoid using low-level call with user-controlled data. Validate inputs.
*/

contract TokenWhale {
    address player;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    string public name = "Simple ERC20 Token";
    string public symbol = "SET";
    uint8 public decimals = 18;

    function TokenWhaleDeploy(address _player) public {
        player = _player;
        totalSupply = 1000;
        balanceOf[player] = 1000;
    }

    event Transfer(address indexed from, address indexed to, uint256 value);

    function transfer(address to, uint256 value) public {
        require(balanceOf[msg.sender] >= value);
        require(balanceOf[to] + value >= balanceOf[to]);

        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
    }

    function approve(address spender, uint256 value) public {
        allowance[msg.sender][spender] = value;
    }

    // VULNERABILITY: Arbitrary call with user-controlled data
    function approveAndCallcode(
        address _spender,
        uint256 _value,
        bytes memory _extraData
    ) public {
        allowance[msg.sender][_spender] = _value;

        // Vulnerable: executes arbitrary code
        (bool success, ) = _spender.call(_extraData);
        require(success);
    }
}
