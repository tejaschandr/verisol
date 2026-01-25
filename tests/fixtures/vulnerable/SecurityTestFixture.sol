// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SecurityTestFixture
 * @dev Contract with common anti-patterns for testing security analyzer detection
 * @notice This is a TEST FIXTURE for validating VeriSol's security detection capabilities
 * @notice NOT FOR PRODUCTION USE - Contains intentional anti-patterns for testing
 */
contract SecurityTestFixture {
    mapping(address => uint256) public balances;
    address public admin;
    uint256 public totalDeposits;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    constructor() {
        admin = msg.sender;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @notice TEST CASE 1: Check-Effects-Interactions pattern violation
     * @dev Security tools should flag that external call precedes state update
     */
    function withdrawWithAntiPattern() public {
        uint256 userBalance = balances[msg.sender];
        require(userBalance > 0, "No balance to withdraw");
        
        // ANTI-PATTERN: External interaction before state change
        // Slither should detect: reentrancy-eth
        (bool sent, ) = msg.sender.call{value: userBalance}("");
        require(sent, "Transfer failed");
        
        // State update after external call (should be before)
        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, userBalance);
    }
    
    /**
     * @notice CORRECT PATTERN: Check-Effects-Interactions properly ordered
     */
    function withdrawCorrectly() public {
        uint256 userBalance = balances[msg.sender];
        require(userBalance > 0, "No balance to withdraw");
        
        // CORRECT: State change before external interaction
        balances[msg.sender] = 0;
        
        (bool sent, ) = msg.sender.call{value: userBalance}("");
        require(sent, "Transfer failed");
        
        emit Withdrawal(msg.sender, userBalance);
    }
    
    /**
     * @notice TEST CASE 2: tx.origin usage
     * @dev Security tools should flag tx.origin for authentication
     */
    function changeAdminWithAntiPattern(address newAdmin) public {
        // ANTI-PATTERN: Using tx.origin for auth
        // Slither should detect: tx-origin
        require(tx.origin == admin, "Not authorized");
        admin = newAdmin;
    }
    
    /**
     * @notice CORRECT PATTERN: Use msg.sender for authentication
     */
    function changeAdminCorrectly(address newAdmin) public {
        require(msg.sender == admin, "Not authorized");
        require(newAdmin != address(0), "Invalid address");
        admin = newAdmin;
    }
    
    /**
     * @notice TEST CASE 3: Missing zero-address validation
     * @dev Security tools should flag missing zero-address check
     */
    function setAdminWithoutValidation(address newAdmin) public {
        require(msg.sender == admin, "Not authorized");
        // ANTI-PATTERN: No zero-address check
        // Slither should detect: missing-zero-check
        admin = newAdmin;
    }
    
    /**
     * @notice TEST CASE 4: Division precision loss
     * @dev Security tools should flag divide-before-multiply
     */
    function calculateShareWithPrecisionLoss(
        uint256 amount, 
        uint256 totalShares
    ) public pure returns (uint256) {
        // ANTI-PATTERN: Division before multiplication
        // Slither should detect: divide-before-multiply
        return amount / totalShares * 100;
    }
    
    /**
     * @notice CORRECT PATTERN: Multiply before divide
     */
    function calculateShareCorrectly(
        uint256 amount, 
        uint256 totalShares
    ) public pure returns (uint256) {
        return (amount * 100) / totalShares;
    }
    
    /**
     * @notice TEST CASE 5: Variable shadowing
     */
    uint256 public storedValue;
    
    // ANTI-PATTERN: Parameter shadows state variable name
    // Slither should detect: shadowing-local
    function setStoredValue(uint256 storedValue) public {
        // This assigns parameter to itself, not updating state
        storedValue = storedValue;
    }
    
    /**
     * @notice CORRECT PATTERN: Clear parameter naming
     */
    function setStoredValueCorrectly(uint256 newValue) public {
        storedValue = newValue;
    }
    
    /**
     * @notice Utility function to check contract balance
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
    
    /**
     * @notice Allow contract to receive ETH
     */
    receive() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
}
