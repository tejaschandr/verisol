// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: First Deposit Bug (Vault Inflation Attack)
pragma solidity ^0.8.15;

/*
Name: First Deposit Bug

Description:
First pool depositor can front-run and inflate the share price.
By depositing 1 wei and then donating tokens directly, the attacker
inflates the price so subsequent depositors get fewer shares due to rounding.

Mitigation:
Mint a minimum amount of shares on first deposit and send to zero address.
(This is what Uniswap V2 does with the first 1000 LP tokens)
*/

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SimplePool {
    IERC20 public loanToken;
    uint public totalShares;

    mapping(address => uint) public balanceOf;

    constructor(address _loanToken) {
        loanToken = IERC20(_loanToken);
    }

    // VULNERABILITY: No minimum shares on first deposit
    function deposit(uint amount) external {
        require(amount > 0, "Amount must be greater than zero");

        uint _shares;
        if (totalShares == 0) {
            _shares = amount;  // First depositor gets 1:1 shares
        } else {
            // Shares can round down to near-zero if price is inflated
            _shares = (amount * totalShares) / loanToken.balanceOf(address(this));
        }

        require(
            loanToken.transferFrom(msg.sender, address(this), amount),
            "TransferFrom failed"
        );
        balanceOf[msg.sender] += _shares;
        totalShares += _shares;
    }

    function withdraw(uint shares) external {
        require(shares > 0, "Shares must be greater than zero");
        require(balanceOf[msg.sender] >= shares, "Insufficient balance");

        uint tokenAmount = (shares * loanToken.balanceOf(address(this))) /
            totalShares;

        balanceOf[msg.sender] -= shares;
        totalShares -= shares;

        require(loanToken.transfer(msg.sender, tokenAmount), "Transfer failed");
    }
}
