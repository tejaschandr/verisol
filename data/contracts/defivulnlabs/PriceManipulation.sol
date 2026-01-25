// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Price Manipulation
pragma solidity ^0.8.18;

/*
Name: Price Manipulation

Description:
The SimplePool uses balanceOf for price calculation, which can be manipulated
via flash loans. An attacker can borrow tokens, change the pool balance,
get a favorable exchange rate, then repay the loan.

Mitigation:
Use a manipulation-resistant oracle like Chainlink or TWAP.
*/

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SimplePool {
    IERC20 public USDaToken;
    IERC20 public USDbToken;

    constructor(address _USDa, address _USDb) {
        USDaToken = IERC20(_USDa);
        USDbToken = IERC20(_USDb);
    }

    // VULNERABILITY: Price based on spot balance - manipulable via flash loan
    function getPrice() public view returns (uint256) {
        uint256 USDaAmount = USDaToken.balanceOf(address(this));
        uint256 USDbAmount = USDbToken.balanceOf(address(this));

        if (USDaAmount == 0) {
            return 0;
        }

        uint256 USDaPrice = (USDbAmount * (10 ** 18)) / USDaAmount;
        return USDaPrice;
    }

    function flashLoan(
        uint256 amount,
        address borrower,
        bytes calldata data
    ) public {
        uint256 balanceBefore = USDaToken.balanceOf(address(this));
        require(balanceBefore >= amount, "Not enough liquidity");
        require(
            USDaToken.transfer(borrower, amount),
            "Flashloan transfer failed"
        );
        (bool success, ) = borrower.call(data);
        require(success, "Flashloan callback failed");
        uint256 balanceAfter = USDaToken.balanceOf(address(this));
        require(balanceAfter >= balanceBefore, "Flashloan not repaid");
    }
}

contract SimpleBank {
    IERC20 public token;
    SimplePool public pool;
    IERC20 public payoutToken;

    constructor(address _token, address _pool, address _payoutToken) {
        token = IERC20(_token);
        pool = SimplePool(_pool);
        payoutToken = IERC20(_payoutToken);
    }

    // VULNERABILITY: Uses manipulable pool price
    function exchange(uint256 amount) public {
        require(
            token.transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );
        uint256 price = pool.getPrice();
        require(price > 0, "Price cannot be zero");
        uint256 tokensToReceive = (amount * price) / (10 ** 18);
        require(
            payoutToken.transfer(msg.sender, tokensToReceive),
            "Payout transfer failed"
        );
    }
}
