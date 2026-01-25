// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Uninitialized Proxy
pragma solidity ^0.8.18;

/*
Name: Uninitialized Proxy Vulnerability

Description:
If a proxy's implementation contract is not initialized, anyone can call
initialize() and become the owner/upgrader. This allows them to upgrade
to a malicious implementation.

Mitigation:
Always initialize implementation contracts, or use constructor-based initialization.
*/

contract Engine {
    address public upgrader;
    uint256 public horsePower;
    bool private initialized;

    // VULNERABILITY: Anyone can call initialize if not called during deployment
    function initialize() external {
        require(!initialized, "Already initialized");
        initialized = true;
        horsePower = 1000;
        upgrader = msg.sender;
    }

    function upgradeToAndCall(address newImplementation, bytes memory data) external {
        require(msg.sender == upgrader, "Can't upgrade");
        // Upgrade logic...
        if (data.length > 0) {
            (bool success, ) = newImplementation.delegatecall(data);
            require(success, "Call failed");
        }
    }
}
