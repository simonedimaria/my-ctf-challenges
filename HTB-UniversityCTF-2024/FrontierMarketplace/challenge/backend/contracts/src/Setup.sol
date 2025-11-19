// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { FrontierMarketplace } from "./FrontierMarketplace.sol";
import { FrontierNFT } from "./FrontierNFT.sol";

contract Setup {
    FrontierMarketplace public immutable TARGET;
    uint256 public constant PLAYER_STARTING_BALANCE = 20 ether;
    uint256 public constant NFT_VALUE = 10 ether;
    
    event DeployedTarget(address at);

    constructor() payable {
        TARGET = new FrontierMarketplace();
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return (
            address(msg.sender).balance > PLAYER_STARTING_BALANCE - NFT_VALUE && 
            FrontierNFT(TARGET.frontierNFT()).balanceOf(msg.sender) > 0
        );
    }
}
