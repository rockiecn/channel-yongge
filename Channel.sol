// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "./Owned.sol";
import "./AdminOwned.sol";
import "./libraries/Recover.sol";
import "./interfaces/ChannelIn.sol";

contract Channel is Owned, ChannelIn {
    using Recover for bytes32;

    address payable channelSender; //payer
    address[] channelRecipients; //receiver
    mapping(address => mapping(uint => bool)) nonces; //avoid replay attack

    uint256 startDate; //start date
    uint256 timeOut; //number of seconds to time out

    adminOwned admin = adminOwned(0x8026796Fd7cE63EAe824314AA5bacF55643e893d); //adminOwned-contract address
    uint16 constant version = 1; //contract version；

    receive() external payable {}

    constructor(address[] memory to, uint256 timeout) payable {
        uint16 bannedVersion = admin.getChannelBannedVersion();
        require(bannedVersion < version, "deploy channel is banned");
        require(timeout > 0);
        channelRecipients = to;
        channelSender = payable(msg.sender);
        startDate = block.timestamp;
        timeOut = timeout;
    }

    // called by receiver.
    function DemandPayment(bytes32 hash, uint256 value, uint nonce, bytes memory sign) external payable override {
        require(isRecipient(msg.sender), "illegal caller");
        require(!nonces[msg.sender][nonce], "illegal nonce");

        bytes32 proof = keccak256(abi.encodePacked(address(this), value, nonce, msg.sender));
        require(proof == hash, "illegal hash");

        address send = hash.recover(sign);
        require(send == channelSender, "illegal sig");

        nonces[msg.sender][nonce] = true;

        payable(msg.sender).transfer(value); //pay value to receiver
        emit channelPay(channelSender, msg.sender, value);
    }

    function isRecipient(address recipient) internal view returns(bool) {
        for(uint256 i=0; i<channelRecipients.length; i++){
            if(channelRecipients[i] == recipient){
                return true;
            }
        }
        return false;
    }

    // user call
    function ChannelTimeout() external override {
        require(startDate + timeOut > startDate);
        require(startDate + timeOut <= block.timestamp, "Time is not up");
        selfdestruct(channelSender);
    }

    function GetInfo()
        external
        view
        override
        returns (
            uint256,
            uint256,
            address,
            address[] memory
        )
    {
        return (startDate, timeOut, channelSender, channelRecipients);
    }

    function GetNonceValue(address recipient, uint nonce) external view returns(bool){
        return nonces[recipient][nonce];
    }

    function Extend(uint256 addTime) external override onlyOwner {
        uint16 bannedVersion = admin.getChannelBannedVersion();
        require(bannedVersion < version, "extend is banned");
        require(addTime > 0); // 只能延长
        uint256 timeout = timeOut + addTime;
        require(timeout > timeOut);
        timeOut = timeout;
    }
}