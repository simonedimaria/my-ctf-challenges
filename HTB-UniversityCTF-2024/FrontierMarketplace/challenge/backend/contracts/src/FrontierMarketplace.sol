// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { FrontierNFT } from "./FrontierNFT.sol";

contract FrontierMarketplace {
    uint256 public constant TOKEN_VALUE = 10 ether;
    FrontierNFT public frontierNFT;
    address public owner;

    event NFTMinted(address indexed buyer, uint256 indexed tokenId);
    event NFTRefunded(address indexed seller, uint256 indexed tokenId);

    constructor() {
        frontierNFT = new FrontierNFT(address(this));
        owner = msg.sender;
    }

    function buyNFT() public payable returns (uint256) {
        require(msg.value == TOKEN_VALUE, "FrontierMarketplace: Incorrect payment amount");
        uint256 tokenId = frontierNFT.mint(msg.sender);
        emit NFTMinted(msg.sender, tokenId);
        return tokenId;
    }
    
    function refundNFT(uint256 tokenId) public {
        require(frontierNFT.ownerOf(tokenId) == msg.sender, "FrontierMarketplace: Only owner can refund NFT");
        frontierNFT.transferFrom(msg.sender, address(this), tokenId);
        payable(msg.sender).transfer(TOKEN_VALUE);
        emit NFTRefunded(msg.sender, tokenId);
    }
}
