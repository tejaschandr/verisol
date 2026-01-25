// SPDX-License-Identifier: MIT
// A simple staking contract with proper security measures
// Status: Clean - Follows best practices

pragma solidity ^0.8.18;

contract SimpleStaking {
    address public owner;
    uint256 public rewardRate = 100; // 1% per period (basis points)
    uint256 public stakingPeriod = 1 days;

    struct Stake {
        uint256 amount;
        uint256 timestamp;
        uint256 claimed;
    }

    mapping(address => Stake) public stakes;

    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 reward);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function stake() public payable {
        require(msg.value > 0, "Must stake something");
        require(stakes[msg.sender].amount == 0, "Already staking");

        stakes[msg.sender] = Stake({
            amount: msg.value,
            timestamp: block.timestamp,
            claimed: 0
        });

        emit Staked(msg.sender, msg.value);
    }

    function calculateReward(address _user) public view returns (uint256) {
        Stake memory userStake = stakes[_user];
        if (userStake.amount == 0) return 0;

        uint256 duration = block.timestamp - userStake.timestamp;
        uint256 periods = duration / stakingPeriod;
        uint256 reward = (userStake.amount * rewardRate * periods) / 10000;

        return reward - userStake.claimed;
    }

    function claimReward() public {
        uint256 reward = calculateReward(msg.sender);
        require(reward > 0, "No reward to claim");
        require(address(this).balance >= reward, "Insufficient contract balance");

        stakes[msg.sender].claimed += reward;

        (bool success, ) = msg.sender.call{value: reward}("");
        require(success, "Transfer failed");

        emit RewardClaimed(msg.sender, reward);
    }

    function unstake() public {
        Stake memory userStake = stakes[msg.sender];
        require(userStake.amount > 0, "Not staking");

        uint256 amount = userStake.amount;
        delete stakes[msg.sender];

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Unstaked(msg.sender, amount);
    }

    // Owner can fund the contract for rewards
    function fundRewards() public payable onlyOwner {}

    function setRewardRate(uint256 _rate) public onlyOwner {
        require(_rate <= 1000, "Rate too high"); // Max 10%
        rewardRate = _rate;
    }
}
