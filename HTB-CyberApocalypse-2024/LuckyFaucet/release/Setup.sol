// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.7.6;

import {LuckyFaucet} from "./LuckyFaucet.sol";

contract Setup {
    LuckyFaucet public immutable TARGET;

    constructor() payable {
        TARGET = new LuckyFaucet{value: 500 ether}();
    }

    function isSolved() public view returns (bool) {
        return msg.sender.balance >= 10 ether;
    }
}
