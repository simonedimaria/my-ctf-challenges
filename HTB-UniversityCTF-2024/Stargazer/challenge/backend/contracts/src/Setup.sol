// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Stargazer } from "./Stargazer.sol";
import { StargazerKernel } from "./StargazerKernel.sol";

contract Setup {
    Stargazer public immutable TARGET_PROXY;
    StargazerKernel public immutable TARGET_IMPL;

    event DeployedTarget(address proxy, address implementation);

    constructor(bytes memory signature) payable {
        TARGET_IMPL = new StargazerKernel();
        
        string[] memory starNames = new string[](1);
        starNames[0] = "Nova-GLIM_007";
        bytes memory initializeCall = abi.encodeCall(TARGET_IMPL.initialize, starNames);
        TARGET_PROXY = new Stargazer(address(TARGET_IMPL), initializeCall);
        
        bytes memory createPASKATicketCall = abi.encodeCall(TARGET_IMPL.createPASKATicket, (signature));
        (bool success, ) = address(TARGET_PROXY).call(createPASKATicketCall);
        require(success);

        string memory starName = "Starry-SPURR_001";
        bytes memory commitStarSightingCall = abi.encodeCall(TARGET_IMPL.commitStarSighting, (starName));
        (success, ) = address(TARGET_PROXY).call(commitStarSightingCall);
        require(success);

        emit DeployedTarget(address(TARGET_PROXY), address(TARGET_IMPL));
    }

    function isSolved() public returns (bool) {
        bool success;
        bytes memory getStarSightingsCall;
        bytes memory returnData;

        getStarSightingsCall = abi.encodeCall(TARGET_IMPL.getStarSightings, ("Nova-GLIM_007"));
        (success, returnData) = address(TARGET_PROXY).call(getStarSightingsCall);
        require(success, "Setup: failed external call.");
        uint256[] memory novaSightings = abi.decode(returnData, (uint256[]));
        
        getStarSightingsCall = abi.encodeCall(TARGET_IMPL.getStarSightings, ("Starry-SPURR_001"));
        (success, returnData) = address(TARGET_PROXY).call(getStarSightingsCall);
        require(success, "Setup: failed external call.");
        uint256[] memory starrySightings = abi.decode(returnData, (uint256[]));
        
        return (novaSightings.length >= 2 && starrySightings.length >= 2);
    }
}
