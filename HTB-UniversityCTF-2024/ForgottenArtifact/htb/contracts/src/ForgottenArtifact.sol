// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract ForgottenArtifact {
    uint256 public lastSighting;

    struct Artifact {
        uint32 origin;
        address discoverer;
    }

    constructor(uint32 _origin, address _discoverer) {
        Artifact storage starrySpurr;
        bytes32 seed = keccak256(abi.encodePacked(block.number, block.timestamp, msg.sender));
        assembly { starrySpurr.slot := seed }
        starrySpurr.origin = _origin;
        starrySpurr.discoverer = _discoverer;
        lastSighting = _origin;
    }

    function discover(bytes32 _artifactLocation) public {
        Artifact storage starrySpurr;
        assembly { starrySpurr.slot := _artifactLocation }
        require(starrySpurr.origin != 0, "ForgottenArtifact: unknown artifact location.");
        starrySpurr.discoverer = msg.sender;
        lastSighting = block.timestamp;
    }
}
