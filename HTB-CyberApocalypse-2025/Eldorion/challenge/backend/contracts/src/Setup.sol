// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Eldorion } from "./Eldorion.sol";

contract Setup {
    Eldorion public immutable TARGET;
    
    event DeployedTarget(address at);

    constructor() payable {
        TARGET = new Eldorion();
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return TARGET.isDefeated();
    }
}
