// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Signature Replay
pragma solidity ^0.8.18;

/*
Name: Signature Replay Vulnerability

Description:
The same signature can be used multiple times to execute a function if the contract
doesn't properly implement nonce or domain separation. This allows attackers to
replay valid signatures across different contracts or multiple times.

Mitigation:
Implement nonces to prevent replay on the same contract, and include chain ID and
contract address in the signature to prevent cross-contract/cross-chain replay.
*/

contract TokenWhale {
    address player;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    string public name = "Simple ERC20 Token";
    string public symbol = "SET";
    uint8 public decimals = 18;
    mapping(address => uint256) nonces;

    function TokenWhaleDeploy(address _player) public {
        player = _player;
        totalSupply = 2000;
        balanceOf[player] = 2000;
    }

    function transfer(address to, uint256 value) public {
        require(balanceOf[msg.sender] >= value);
        require(balanceOf[to] + value >= balanceOf[to]);
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
    }

    // VULNERABILITY: Signature can be replayed across contracts
    function transferProxy(
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeUgt,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) public returns (bool) {
        uint256 nonce = nonces[_from];
        // Missing contract address in hash - can replay on other contracts
        bytes32 h = keccak256(
            abi.encodePacked(_from, _to, _value, _feeUgt, nonce)
        );
        if (_from != ecrecover(h, _v, _r, _s)) revert();

        balanceOf[_to] += _value;
        balanceOf[msg.sender] += _feeUgt;
        balanceOf[_from] -= _value + _feeUgt;
        nonces[_from] = nonce + 1;
        return true;
    }
}

// Vulnerable to cross-contract replay - same signature works on this contract
contract SixEyeToken {
    address player;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    string public name = "Six Eye Token";
    string public symbol = "SIX";
    uint8 public decimals = 18;
    mapping(address => uint256) nonces;

    function TokenWhaleDeploy(address _player) public {
        player = _player;
        totalSupply = 2000;
        balanceOf[player] = 2000;
    }

    function transfer(address to, uint256 value) public {
        require(balanceOf[msg.sender] >= value);
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
    }

    // VULNERABILITY: No nonce increment - same signature replayable
    function transferProxy(
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeUgt,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) public returns (bool) {
        uint256 nonce = nonces[_from];
        bytes32 h = keccak256(
            abi.encodePacked(_from, _to, _value, _feeUgt, nonce)
        );
        if (_from != ecrecover(h, _v, _r, _s)) revert();

        balanceOf[_to] += _value;
        balanceOf[msg.sender] += _feeUgt;
        balanceOf[_from] -= _value + _feeUgt;
        // Missing: nonces[_from] = nonce + 1;
        return true;
    }
}
