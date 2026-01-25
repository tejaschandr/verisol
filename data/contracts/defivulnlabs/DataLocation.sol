// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Data Location Confusion
pragma solidity ^0.8.18;

/*
Name: Data Location Confusion Vulnerability

Description:
Using 'memory' instead of 'storage' for struct references causes changes
to not persist. The function appears to update state but actually only
modifies a memory copy that's discarded after the function returns.

Mitigation:
Use explicit storage references when modifying state variables.
*/

contract Array {
    mapping(address => UserInfo) public userInfo;

    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
    }

    // VULNERABILITY: Uses memory - changes don't persist
    function updaterewardDebt(uint amount) public {
        UserInfo memory user = userInfo[msg.sender];  // memory copy
        user.rewardDebt = amount;  // modifies copy, not storage
    }

    // Correct version using storage
    function fixedupdaterewardDebt(uint amount) public {
        UserInfo storage user = userInfo[msg.sender];  // storage reference
        user.rewardDebt = amount;  // modifies actual storage
    }
}
