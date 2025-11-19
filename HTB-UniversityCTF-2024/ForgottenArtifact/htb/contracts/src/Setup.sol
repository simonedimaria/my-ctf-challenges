// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { ForgottenArtifact } from "./ForgottenArtifact.sol";

contract Setup {
    uint256 public constant ARTIFACT_ORIGIN = 0xdead;
    ForgottenArtifact public immutable TARGET;
    
    event DeployedTarget(address at);

    constructor() payable {
        TARGET = new ForgottenArtifact(uint32(ARTIFACT_ORIGIN), address(0));
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return TARGET.lastSighting() > ARTIFACT_ORIGIN;
    }
}
