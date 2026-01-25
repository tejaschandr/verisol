// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Reentrancy
pragma solidity ^0.8.18;

/*
Name: Reentrancy Vulnerability

Description:
The EtherStore Reentrancy Vulnerability is a flaw in the smart contract design that allows
an attacker to exploit reentrancy and withdraw more funds than they are entitled to.
The vulnerability arises due to the withdrawFunds function where Ether is transferred
to the attacker's address before updating their balance.

Mitigation:
Follow check-effect-interaction and use OpenZeppelin Reentrancy Guard.
*/

contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        // VULNERABILITY: External call before state update
        (bool send, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(send, "send failed");

        // State update AFTER external call - vulnerable to reentrancy
        if (balances[msg.sender] >= _weiToWithdraw) {
            balances[msg.sender] -= _weiToWithdraw;
        }
    }
}

// Remediated version with reentrancy guard
contract EtherStoreRemediated {
    mapping(address => uint256) public balances;
    bool internal locked;

    modifier nonReentrant() {
        require(!locked, "No re-entrancy");
        locked = true;
        _;
        locked = false;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public nonReentrant {
        require(balances[msg.sender] >= _weiToWithdraw);
        balances[msg.sender] -= _weiToWithdraw;
        (bool send, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(send, "send failed");
    }
}
