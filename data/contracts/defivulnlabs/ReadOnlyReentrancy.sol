// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Read-Only Reentrancy
pragma solidity ^0.8.18;

/*
Name: Read-Only Reentrancy Vulnerability

Description:
Read-only reentrancy occurs when a contract reads state from another contract
during an external call, while that state is in an inconsistent state.
This is common with LP token pricing during Curve remove_liquidity calls.

Mitigation:
Check for reentrancy in read functions, or use reentrancy guards that
protect reads as well as writes.
*/

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface ICurvePool {
    function get_virtual_price() external view returns (uint);
    function remove_liquidity(uint lp, uint[2] calldata min_amounts) external returns (uint[2] memory);
}

// Vulnerable contract that reads price during reentrancy
contract VulnContract {
    IERC20 public lpToken;
    ICurvePool public pool;

    mapping(address => uint) public balanceOf;

    constructor(address _lpToken, address _pool) {
        lpToken = IERC20(_lpToken);
        pool = ICurvePool(_pool);
    }

    function stake(uint amount) external {
        lpToken.transferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender] += amount;
    }

    function unstake(uint amount) external {
        balanceOf[msg.sender] -= amount;
        lpToken.transfer(msg.sender, amount);
    }

    // VULNERABILITY: Reads price that can be manipulated during reentrancy
    function getReward() external view returns (uint) {
        // During remove_liquidity callback, get_virtual_price is inflated
        uint reward = (balanceOf[msg.sender] * pool.get_virtual_price()) / 1 ether;
        return reward;
    }
}
