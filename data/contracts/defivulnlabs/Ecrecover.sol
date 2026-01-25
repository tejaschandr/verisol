// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: ecrecover returns address(0)
pragma solidity ^0.8.18;

/*
Name: ecrecover returns address(0)

Description:
ecrecover returns address(0) for invalid signatures (e.g., invalid v value).
If the contract compares against an uninitialized admin (also address(0)),
an attacker can bypass authentication.

Mitigation:
Always check that ecrecover result is not address(0).
*/

contract SimpleBank {
    mapping(address => uint256) private balances;
    address Admin; // default is address(0)

    function getBalance(address _account) public view returns (uint256) {
        return balances[_account];
    }

    // VULNERABILITY: No check for address(0) from ecrecover
    function transfer(
        address _to,
        uint256 _amount,
        bytes32 _hash,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) public {
        require(_to != address(0), "Invalid recipient");

        address signer = ecrecover(_hash, _v, _r, _s);
        // Missing: require(signer != address(0), "Invalid signature");
        require(signer == Admin, "Invalid signature"); // Passes if both are 0!

        balances[_to] += _amount;
    }
}
