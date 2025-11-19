// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

contract Enlistment {
    bytes16 public publicKey;
    bytes16 private privateKey;
    mapping(address => bool) public enlisted;
    
    constructor(bytes32 _key) {
        publicKey = bytes16(_key);
        privateKey = bytes16(_key << (16*8));
    }

    function enlist(bytes32 _proofHash) public {
        bool authorized = _proofHash == keccak256(abi.encodePacked(publicKey, privateKey));
        require(authorized, "Invalid proof hash");
        enlisted[msg.sender] = true;
    }
}
