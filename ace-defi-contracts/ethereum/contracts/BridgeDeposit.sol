// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title BridgeDeposit
 * @dev Ethereum bridge contract for ACE DeFi cross-chain deposits
 *
 * Users deposit assets here and specify their ACE Chain recipient.
 * The Relayer monitors this contract for DepositEvent and relays to ACE.
 */
contract BridgeDeposit is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    /// ACE Phase A mints deposits into u64 accounting with a conservative half-range cap.
    uint256 public constant ACE_MAX_DEPOSIT_AMOUNT = type(uint64).max / 2;

    /// Event emitted when a user deposits assets
    event Deposit(
        bytes32 indexed depositId,
        bytes32 indexed intentId,
        address indexed user,
        address token,
        uint256 amount,
        bytes32 aceRecipient,
        uint256 timestamp
    );

    /// Event emitted when an asset is withdrawn (emergency only)
    event Withdrawal(
        address indexed token,
        address indexed recipient,
        uint256 amount
    );

    /// Event emitted when an emergency withdrawal is scheduled.
    event EmergencyWithdrawalScheduled(
        bytes32 indexed operationId,
        address indexed token,
        address indexed recipient,
        uint256 amount,
        uint256 nonce,
        uint256 executableAt
    );

    /// Event emitted when a scheduled emergency withdrawal is cancelled.
    event EmergencyWithdrawalCancelled(bytes32 indexed operationId);

    /// USDT token address on Ethereum mainnet
    IERC20 public usdt;

    /// Source-chain deposit IDs already accepted by this custody contract.
    mapping(bytes32 => bool) public acceptedDeposits;

    /// Owner address (governance)
    address public governance;

    /// Monotonic nonce included in deposit IDs.
    uint256 public depositNonce;

    /// Monotonic nonce included in emergency withdrawal operation IDs.
    uint256 public emergencyNonce;

    /// Delay before owner can execute an emergency withdrawal.
    uint256 public constant EMERGENCY_WITHDRAW_DELAY = 2 days;

    /// Scheduled emergency withdrawal execution time.
    mapping(bytes32 => uint256) public emergencyWithdrawalExecutableAt;

    /// Scheduled emergency withdrawal parameter hash.
    mapping(bytes32 => bytes32) public emergencyWithdrawalParamsHash;

    /**
     * @dev Initialize the bridge with USDT token address
     * @param _usdt USDT token contract address
     */
    constructor(address _usdt) Ownable(msg.sender) {
        require(_usdt != address(0), "Invalid USDT address");
        usdt = IERC20(_usdt);
        governance = msg.sender;
    }

    /**
     * @dev Deposit USDT to ACE Chain
     * @param amount Amount of USDT to deposit (in wei)
     * @param intentId ACE ConvertIntent identifier committed by the user
     * @param aceRecipient Recipient address on ACE Chain (bytes32)
     * @return depositId Unique identifier for this deposit
     */
    function deposit(
        uint256 amount,
        bytes32 intentId,
        bytes32 aceRecipient
    ) external nonReentrant returns (bytes32) {
        require(amount > 0, "Amount must be > 0");
        require(amount <= ACE_MAX_DEPOSIT_AMOUNT, "Amount exceeds ACE limit");
        require(intentId != bytes32(0), "Invalid intentId");
        require(aceRecipient != bytes32(0), "Invalid ACE recipient");

        // Transfer USDT from user to contract (must have approved first).
        uint256 balanceBefore = usdt.balanceOf(address(this));
        usdt.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = usdt.balanceOf(address(this)) - balanceBefore;
        require(received > 0, "No tokens received");
        require(received <= ACE_MAX_DEPOSIT_AMOUNT, "Received exceeds ACE limit");

        // Generate unique deposit ID
        uint256 nonce = depositNonce++;
        bytes32 depositId = keccak256(
            abi.encode(
                "ACE_DEFI_DEPOSIT_V1",
                intentId,
                block.chainid,
                address(this),
                nonce,
                msg.sender,
                address(usdt),
                received,
                aceRecipient
            )
        );
        acceptedDeposits[depositId] = true;

        // Emit event for relayer to pick up
        emit Deposit(
            depositId,
            intentId,
            msg.sender,
            address(usdt),
            received,
            aceRecipient,
            block.timestamp
        );

        return depositId;
    }

    /**
     * @dev Deposit ERC20 token (generic)
     * @param token Token address
     * @param amount Amount to deposit
     * @param intentId ACE ConvertIntent identifier committed by the user
     * @param aceRecipient Recipient on ACE Chain
     * @return depositId Unique deposit identifier
     */
    function depositToken(
        address token,
        uint256 amount,
        bytes32 intentId,
        bytes32 aceRecipient
    ) external nonReentrant returns (bytes32) {
        require(token != address(0), "Invalid token address");
        require(amount > 0, "Amount must be > 0");
        require(amount <= ACE_MAX_DEPOSIT_AMOUNT, "Amount exceeds ACE limit");
        require(intentId != bytes32(0), "Invalid intentId");
        require(aceRecipient != bytes32(0), "Invalid ACE recipient");

        // Transfer token from user to contract.
        IERC20 tokenContract = IERC20(token);
        uint256 balanceBefore = tokenContract.balanceOf(address(this));
        tokenContract.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = tokenContract.balanceOf(address(this)) - balanceBefore;
        require(received > 0, "No tokens received");
        require(received <= ACE_MAX_DEPOSIT_AMOUNT, "Received exceeds ACE limit");

        // Generate deposit ID
        uint256 nonce = depositNonce++;
        bytes32 depositId = keccak256(
            abi.encode(
                "ACE_DEFI_DEPOSIT_V1",
                intentId,
                block.chainid,
                address(this),
                nonce,
                msg.sender,
                token,
                received,
                aceRecipient
            )
        );
        acceptedDeposits[depositId] = true;

        // Emit event
        emit Deposit(
            depositId,
            intentId,
            msg.sender,
            token,
            received,
            aceRecipient,
            block.timestamp
        );

        return depositId;
    }

    /**
     * @dev Emergency withdrawal by owner only
     * @param token Token to withdraw
     * @param recipient Address to send to
     * @param amount Amount to withdraw
     */
    function scheduleEmergencyWithdraw(
        address token,
        address recipient,
        uint256 amount
    ) external onlyOwner returns (bytes32 operationId) {
        require(token != address(0), "Invalid token");
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0, "Amount must be > 0");

        uint256 nonce = emergencyNonce++;
        operationId = keccak256(
            abi.encode(
                "ACE_DEFI_EMERGENCY_WITHDRAW_V1",
                block.chainid,
                address(this),
                nonce,
                token,
                recipient,
                amount
            )
        );
        uint256 executableAt = block.timestamp + EMERGENCY_WITHDRAW_DELAY;
        emergencyWithdrawalExecutableAt[operationId] = executableAt;
        emergencyWithdrawalParamsHash[operationId] = keccak256(
            abi.encode(token, recipient, amount)
        );

        emit EmergencyWithdrawalScheduled(
            operationId,
            token,
            recipient,
            amount,
            nonce,
            executableAt
        );
    }

    function cancelEmergencyWithdraw(bytes32 operationId) external onlyOwner {
        require(
            emergencyWithdrawalExecutableAt[operationId] != 0,
            "Operation not scheduled"
        );
        delete emergencyWithdrawalExecutableAt[operationId];
        delete emergencyWithdrawalParamsHash[operationId];
        emit EmergencyWithdrawalCancelled(operationId);
    }

    /**
     * @dev Execute a scheduled emergency withdrawal by owner only.
     * @param token Token to withdraw
     * @param recipient Address to send to
     * @param amount Amount to withdraw
     */
    function executeEmergencyWithdraw(
        bytes32 operationId,
        address token,
        address recipient,
        uint256 amount
    ) external onlyOwner {
        uint256 executableAt = emergencyWithdrawalExecutableAt[operationId];
        require(executableAt != 0, "Operation not scheduled");
        require(block.timestamp >= executableAt, "Timelock not expired");
        require(
            emergencyWithdrawalParamsHash[operationId] ==
                keccak256(abi.encode(token, recipient, amount)),
            "Operation parameters mismatch"
        );

        delete emergencyWithdrawalExecutableAt[operationId];
        delete emergencyWithdrawalParamsHash[operationId];
        IERC20(token).safeTransfer(recipient, amount);
        emit Withdrawal(token, recipient, amount);
    }

    /**
     * @dev Check if this source-chain contract accepted a deposit ID.
     * @param depositId Deposit identifier
     * @return bool Whether this deposit was accepted into custody
     */
    function isAcceptedDeposit(bytes32 depositId) external view returns (bool) {
        return acceptedDeposits[depositId];
    }

    /**
     * @dev Get USDT balance of this contract
     * @return Balance in wei
     */
    function getBalance() external view returns (uint256) {
        return usdt.balanceOf(address(this));
    }

    /**
     * @dev Get token balance
     * @param token Token address
     * @return Balance in wei
     */
    function getTokenBalance(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    /**
     * @dev Change governance address
     * @param newGovernance New governance address
     */
    function setGovernance(address newGovernance) external onlyOwner {
        require(newGovernance != address(0), "Invalid governance address");
        governance = newGovernance;
        _transferOwnership(newGovernance);
    }
}
