// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Exchange is AccessControlEnumerable, Ownable {
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    using SafeERC20 for IERC20;

    address public token;

    mapping(bytes => bool) private claimedSignatures;

    event Deposit(uint256 amount);
    event Withdraw(uint256 amount, uint256 nonce);
    event RecoveredERC20(address token, uint256 amount);

    constructor(address tokenAddress, address _signer) {
        token = tokenAddress;

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(SIGNER_ROLE, _signer);
    }

    function recoverERC20(address tokenAddress, uint256 tokenAmount)
        external
        onlyOwner
    {
        IERC20(tokenAddress).safeTransfer(owner(), tokenAmount);
        emit RecoveredERC20(tokenAddress, tokenAmount);
    }

    function setTokenAddress(address tokenAddress) external onlyOwner {
        token = tokenAddress;
    }

    function deposit(uint256 amount) external {
        IERC20(token).safeTransferFrom(_msgSender(), address(this), amount);

        emit Deposit(amount);
    }

    function withdraw(
        uint256 amount,
        uint256 nonce,
        bytes memory signature
    ) external {
        require(!claimedSignatures[signature], "signature already claimed");

        bytes32 hashWithoutPrefix = keccak256(
            abi.encodePacked(
                toUint(_msgSender()),
                amount,
                nonce,
                toUint(address(this))
            )
        );
        verifySigner(hashWithoutPrefix, signature);

        claimedSignatures[signature] = true;

        IERC20(token).safeTransfer(_msgSender(), amount);

        emit Withdraw(amount, nonce);
    }

    function verifySigner(bytes32 hashWithoutPrefix, bytes memory signature)
        internal
        view
    {
        // This recreates the message hash that was signed on the client.
        bytes32 hash = prefixed(hashWithoutPrefix);
        // Verify that the message's signer is the owner
        address recoveredSigner = recoverSigner(hash, signature);

        require(hasRole(SIGNER_ROLE, recoveredSigner), "must be signer");
    }

    function recoverSigner(bytes32 message, bytes memory sig)
        internal
        pure
        returns (address)
    {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);

        return ecrecover(message, v, r, s);
    }

    function splitSignature(bytes memory sig)
        internal
        pure
        returns (
            uint8 v,
            bytes32 r,
            bytes32 s
        )
    {
        require(sig.length == 65);

        assembly {
            // first 32 bytes, after the length prefix.
            r := mload(add(sig, 32))
            // second 32 bytes.
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes).
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
            );
    }

    function toUint(address _address) internal pure virtual returns (uint256) {
        return uint256(uint160(_address));
    }
}
