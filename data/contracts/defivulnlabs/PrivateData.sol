// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Private Data Exposure
pragma solidity ^0.8.18;

/*
Name: Private Data Exposure

Description:
Solidity stores variables in slots. All data on-chain, whether public or private,
can be read. It is possible to read private data by predicting the storage slot.
Sensitive data like passwords should never be stored on-chain.

Mitigation:
Avoid storing sensitive data on-chain. Use off-chain storage or encryption.
*/

contract Vault {
    // VULNERABILITY: Private doesn't mean hidden - all storage is readable
    uint256 private password;  // slot 0

    struct User {
        uint id;
        bytes32 password;
    }

    User[] public users;  // slot 1
    mapping(uint => User) public idToUser;  // slot 2

    constructor(uint256 _password) {
        password = _password;
        User memory user = User({id: 0, password: bytes32(_password)});
        users.push(user);
        idToUser[0] = user;
    }

    function getArrayLocation(
        uint slot,
        uint index,
        uint elementSize
    ) public pure returns (bytes32) {
        uint256 a = uint(keccak256(abi.encodePacked(slot))) +
            (index * elementSize);
        return bytes32(a);
    }
}
