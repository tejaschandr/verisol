// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SimpleLending
 * @notice A simplified lending protocol (similar to Aave/Compound concepts)
 * @dev Contains some subtle vulnerabilities for testing
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SimpleLending {
    IERC20 public token;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;

    uint256 public totalDeposits;
    uint256 public totalBorrows;
    uint256 public constant COLLATERAL_RATIO = 150; // 150%
    uint256 public constant LIQUIDATION_THRESHOLD = 120; // 120%

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event Borrow(address indexed user, uint256 amount);
    event Repay(address indexed user, uint256 amount);
    event Liquidation(address indexed user, address indexed liquidator, uint256 amount);

    constructor(address _token) {
        token = IERC20(_token);
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "Amount must be > 0");
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        deposits[msg.sender] += amount;
        totalDeposits += amount;

        emit Deposit(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient deposits");
        require(isHealthy(msg.sender, amount, 0), "Would be undercollateralized");

        deposits[msg.sender] -= amount;
        totalDeposits -= amount;

        require(token.transfer(msg.sender, amount), "Transfer failed");

        emit Withdraw(msg.sender, amount);
    }

    function borrow(uint256 amount) external {
        require(amount > 0, "Amount must be > 0");
        require(isHealthy(msg.sender, 0, amount), "Insufficient collateral");
        require(token.balanceOf(address(this)) >= amount, "Insufficient liquidity");

        borrows[msg.sender] += amount;
        totalBorrows += amount;

        require(token.transfer(msg.sender, amount), "Transfer failed");

        emit Borrow(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        require(borrows[msg.sender] >= amount, "Repaying too much");
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        borrows[msg.sender] -= amount;
        totalBorrows -= amount;

        emit Repay(msg.sender, amount);
    }

    // VULNERABILITY: No access control - anyone can liquidate
    // VULNERABILITY: Price is assumed 1:1, no oracle
    function liquidate(address user, uint256 amount) external {
        uint256 collateral = deposits[user];
        uint256 debt = borrows[user];

        // Check if user is undercollateralized (below 120%)
        require(collateral * 100 < debt * LIQUIDATION_THRESHOLD, "User is healthy");
        require(amount <= debt, "Cannot liquidate more than debt");

        // Transfer debt from liquidator
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        // Calculate collateral to seize (with 5% bonus)
        uint256 collateralToSeize = amount * 105 / 100;
        require(collateralToSeize <= collateral, "Not enough collateral");

        // Update state
        borrows[user] -= amount;
        deposits[user] -= collateralToSeize;
        totalBorrows -= amount;
        totalDeposits -= collateralToSeize;

        // Transfer seized collateral to liquidator
        require(token.transfer(msg.sender, collateralToSeize), "Transfer failed");

        emit Liquidation(user, msg.sender, amount);
    }

    function isHealthy(address user, uint256 withdrawAmount, uint256 borrowAmount) public view returns (bool) {
        uint256 collateral = deposits[user] - withdrawAmount;
        uint256 debt = borrows[user] + borrowAmount;

        if (debt == 0) return true;

        // collateral * 100 >= debt * COLLATERAL_RATIO (150%)
        return collateral * 100 >= debt * COLLATERAL_RATIO;
    }

    function getHealthFactor(address user) external view returns (uint256) {
        if (borrows[user] == 0) return type(uint256).max;
        return deposits[user] * 100 / borrows[user];
    }
}
