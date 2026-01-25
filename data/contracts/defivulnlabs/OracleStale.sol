// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Oracle Stale Price
pragma solidity ^0.8.18;

/*
Name: Oracle Stale Price Vulnerability

Description:
Chainlink price feed latestRoundData is used to retrieve prices, but the response
is not properly validated. Missing checks for staleness, round completeness,
and negative answers can lead to using invalid prices.

Mitigation:
Validate all return values: check answeredInRound >= roundId,
updatedAt > 0, and answer > 0.
*/

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

contract VulnerableOracle {
    AggregatorV3Interface internal priceFeed;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // VULNERABILITY: No validation of oracle response
    function getUnsafePrice() public view returns (int256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        return answer;  // Could be stale, incomplete, or negative
    }

    // Safe implementation with proper validation
    function getSafePrice() public view returns (int256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        require(answeredInRound >= roundId, "Stale price");
        require(updatedAt > 0, "Round not complete");
        require(answer > 0, "Invalid price");

        return answer;
    }
}
