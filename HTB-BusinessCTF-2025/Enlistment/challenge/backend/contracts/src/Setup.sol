// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import { Enlistment } from "./Enlistment.sol";

contract Setup {
    Enlistment public TARGET;
    address public player;

    event DeployedTarget(address at);

    constructor(address _player, bytes32 _key) {
        TARGET = new Enlistment(_key);
        player = _player;
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return TARGET.enlisted(player); 
    }
}
