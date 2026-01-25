// SPDX-License-Identifier: MIT
// Source: DeFiVulnLabs - Classic Reentrancy Example
// Vulnerability: Reentrancy - ETH transferred before balance update

pragma solidity ^0.8.18;

contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: External call before state update
    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        (bool send, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(send, "send failed");

        // State update AFTER external call - classic reentrancy
        if (balances[msg.sender] >= _weiToWithdraw) {
            balances[msg.sender] -= _weiToWithdraw;
        }
    }
}
