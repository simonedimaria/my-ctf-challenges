// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract ForgottenArtifact {
    bytes32 private constant MAIN_STORAGE_LOCATION = 0x183a6125c38840424c4a85fa12bab2ab606c4b6d0e7cc73c0c06ba5300eab500;
    uint256 public lastSighting;
    
    struct Artifact {
        uint32 origin;
        address discoverer;
    }

    constructor(uint32 _origin, address _discoverer) {
        Artifact storage starrySpurr;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, number())
            mstore(add(ptr, 0x20), timestamp())
            mstore(add(ptr, 0x40), caller())
            let seed := keccak256(ptr, 0x60)
            starrySpurr.slot := MAIN_STORAGE_LOCATION
        }
        starrySpurr.origin = _origin;
        starrySpurr.discoverer = _discoverer;
        lastSighting = _origin;
    }

    function discover(bytes32 _artifactLocation) public {
        Artifact storage $;
        assembly { $.slot := _artifactLocation }
        require($.origin == 0xdead, "ForgottenArtifact: unknown artifact location.");
        $.discoverer = msg.sender;
        lastSighting = block.timestamp;
    }
}
