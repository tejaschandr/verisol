// SPDX-License-Identifier: MIT
// Source: DeFiVulnLabs - Unsafe Delegatecall Example
// Vulnerability: Delegatecall to user-controlled address allows storage manipulation

pragma solidity ^0.8.18;

contract Delegate {
    address public owner; // slot0

    function pwn() public {
        owner = msg.sender;
    }
}

contract Proxy {
    address public owner = address(0xdeadbeef); // slot0
    address public delegate;

    constructor(address _delegateAddress) {
        delegate = _delegateAddress;
    }

    // VULNERABLE: Delegatecall in fallback allows arbitrary function execution
    // This modifies Proxy's storage, not Delegate's
    fallback() external {
        (bool suc, ) = delegate.delegatecall(msg.data);
        require(suc, "Delegatecall failed");
    }
}
