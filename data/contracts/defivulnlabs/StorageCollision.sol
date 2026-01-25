// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Storage Collision
pragma solidity ^0.8.18;

/*
Name: Storage Collision Vulnerability

Description:
Proxy and Logic contracts share storage via delegatecall. If they use the same
storage slot for different variables, calling logic functions can overwrite
proxy state (like the implementation address).

Mitigation:
Use consistent storage layout or EIP-1967 storage slots.
*/

contract Proxy {
    address public implementation; // slot 0

    constructor(address _implementation) {
        implementation = _implementation;
    }

    function testcollision() public {
        (bool success, ) = implementation.delegatecall(
            abi.encodeWithSignature("foo(address)", address(this))
        );
        require(success);
    }
}

contract Logic {
    address public GuestAddress; // slot 0 - COLLISION with Proxy.implementation

    function foo(address _addr) public {
        GuestAddress = _addr; // Overwrites Proxy.implementation!
    }
}
