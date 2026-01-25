// SPDX-License-Identifier: MIT
// Vulnerable: Flash loan attack vector - price oracle manipulation
// Source: Common DeFi exploit pattern

pragma solidity ^0.8.18;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableLending {
    IERC20 public collateralToken;
    IERC20 public borrowToken;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    uint256 public constant COLLATERAL_RATIO = 150; // 150% collateralization

    constructor(address _collateralToken, address _borrowToken) {
        collateralToken = IERC20(_collateralToken);
        borrowToken = IERC20(_borrowToken);
    }

    function depositCollateral(uint256 _amount) public {
        collateralToken.transferFrom(msg.sender, address(this), _amount);
        collateral[msg.sender] += _amount;
    }

    // VULNERABLE: Uses spot price from pool balance ratio
    // Attacker can manipulate pool balance with flash loan
    function getPrice() public view returns (uint256) {
        uint256 collateralBalance = collateralToken.balanceOf(address(this));
        uint256 borrowBalance = borrowToken.balanceOf(address(this));

        if (collateralBalance == 0) return 1e18;
        return (borrowBalance * 1e18) / collateralBalance;
    }

    // VULNERABLE: Relies on manipulable price
    function borrow(uint256 _amount) public {
        uint256 price = getPrice();
        uint256 collateralValue = (collateral[msg.sender] * price) / 1e18;
        uint256 maxBorrow = (collateralValue * 100) / COLLATERAL_RATIO;

        require(borrowed[msg.sender] + _amount <= maxBorrow, "Insufficient collateral");

        borrowed[msg.sender] += _amount;
        borrowToken.transfer(msg.sender, _amount);
    }

    function repay(uint256 _amount) public {
        require(borrowed[msg.sender] >= _amount, "Repaying too much");
        borrowToken.transferFrom(msg.sender, address(this), _amount);
        borrowed[msg.sender] -= _amount;
    }

    function withdrawCollateral(uint256 _amount) public {
        require(collateral[msg.sender] >= _amount, "Insufficient collateral");

        uint256 price = getPrice();
        uint256 remainingCollateralValue = ((collateral[msg.sender] - _amount) * price) / 1e18;
        uint256 requiredCollateral = (borrowed[msg.sender] * COLLATERAL_RATIO) / 100;

        require(remainingCollateralValue >= requiredCollateral, "Would be undercollateralized");

        collateral[msg.sender] -= _amount;
        collateralToken.transfer(msg.sender, _amount);
    }
}
