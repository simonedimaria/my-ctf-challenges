// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Voting} from "./Voting.sol";

contract Setup {
    Voting public immutable TARGET;

    constructor() payable {
        require(msg.value == 1 ether);
        TARGET = new Voting();
    }

    function isSolved() public view returns (bool) {
        return (TARGET.WinningParty() == bytes3("UNZ"));
    }
}
