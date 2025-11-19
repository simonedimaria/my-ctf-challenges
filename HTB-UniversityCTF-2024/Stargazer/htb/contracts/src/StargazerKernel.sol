// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract StargazerKernel is UUPSUpgradeable {
    // keccak256(abi.encode(uint256(keccak256("htb.storage.Stargazer")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant __STARGAZER_MEMORIES_LOCATION = 0x8e8af00ddb7b2dfef2ccc4890803445639c579a87f9cda7f6886f80281e2c800;
    
    /// @custom:storage-location erc7201:htb.storage.Stargazer
    struct StargazerMemories {
        uint256 originTimestamp; 
        mapping(bytes32 => uint256[]) starSightings;
        mapping(bytes32 => bool) usedPASKATickets;
        mapping(address => KernelMaintainer) kernelMaintainers;
    }

    struct KernelMaintainer {
        address account;
        PASKATicket[] PASKATickets;
        uint256 PASKATicketsNonce;
    }

    struct PASKATicket {
        bytes32 hashedRequest;
        bytes signature;
    }

    event PASKATicketCreated(PASKATicket ticket);
    event StarSightingRecorded(string starName, uint256 sightingTimestamp);
    event AuthorizedKernelUpgrade(address newImplementation);

    function initialize(string[] memory _pastStarSightings) public initializer onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        $.originTimestamp = block.timestamp;
        $.kernelMaintainers[tx.origin].account = tx.origin;
        for (uint256 i = 0; i < _pastStarSightings.length; i++) {
            bytes32 starId = keccak256(abi.encodePacked(_pastStarSightings[i]));
            $.starSightings[starId].push(block.timestamp);
        }
    }

    function createPASKATicket(bytes memory _signature) public onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        uint256 nonce = $.kernelMaintainers[tx.origin].PASKATicketsNonce;
        bytes32 hashedRequest = _prefixed(
            keccak256(abi.encodePacked("PASKA: Privileged Authorized StargazerKernel Action", nonce))
        );
        PASKATicket memory newTicket = PASKATicket(hashedRequest, _signature);
        _verifyPASKATicket(newTicket);
        $.kernelMaintainers[tx.origin].PASKATickets.push(newTicket);
        $.kernelMaintainers[tx.origin].PASKATicketsNonce++;
        emit PASKATicketCreated(newTicket);
    }

    function commitStarSighting(string memory _starName) public onlyProxy {
        address author = tx.origin;
        PASKATicket memory starSightingCommitRequest = _consumePASKATicket(author);
        StargazerMemories storage $ = _getStargazerMemory();
        bytes32 starId = keccak256(abi.encodePacked(_starName));
        uint256 sightingTimestamp = block.timestamp;
        $.starSightings[starId].push(sightingTimestamp);
        emit StarSightingRecorded(_starName, sightingTimestamp);
    }

    function getStarSightings(string memory _starName) public view onlyProxy returns (uint256[] memory) {
        StargazerMemories storage $ = _getStargazerMemory();
        bytes32 starId = keccak256(abi.encodePacked(_starName));
        return $.starSightings[starId];
    }

    function _getStargazerMemory() private view onlyProxy returns (StargazerMemories storage $) {
        assembly { $.slot := __STARGAZER_MEMORIES_LOCATION }
    }

    function _getKernelMaintainerInfo(address _kernelMaintainer) internal view onlyProxy returns (KernelMaintainer memory) {
        StargazerMemories storage $ = _getStargazerMemory();
        return $.kernelMaintainers[_kernelMaintainer];
    }

    function _authorizeUpgrade(address _newImplementation) internal override onlyProxy {
        address issuer = tx.origin;
        PASKATicket memory kernelUpdateRequest = _consumePASKATicket(issuer);
        emit AuthorizedKernelUpgrade(_newImplementation);
    }

    function _consumePASKATicket(address _kernelMaintainer) internal onlyProxy returns (PASKATicket memory) {
        StargazerMemories storage $ = _getStargazerMemory();
        KernelMaintainer storage maintainer = $.kernelMaintainers[_kernelMaintainer];
        PASKATicket[] storage activePASKATickets = maintainer.PASKATickets;
        require(activePASKATickets.length > 0, "StargazerKernel: no active PASKA tickets.");
        PASKATicket memory ticket = activePASKATickets[activePASKATickets.length - 1];
        bytes32 ticketId = keccak256(abi.encode(ticket));
        $.usedPASKATickets[ticketId] = true;
        activePASKATickets.pop();
        return ticket;
    }

    function _verifyPASKATicket(PASKATicket memory _ticket) internal view onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        address signer = _recoverSigner(_ticket.hashedRequest, _ticket.signature);
        require(_isKernelMaintainer(signer), "StargazerKernel: signer is not a StargazerKernel maintainer.");
        bytes32 ticketId = keccak256(abi.encode(_ticket));
        require(!$.usedPASKATickets[ticketId], "StargazerKernel: PASKA ticket already used.");
    }

    function _recoverSigner(bytes32 _message, bytes memory _signature) internal view onlyProxy returns (address) {
        require(_signature.length == 65, "StargazerKernel: invalid signature length.");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }
        require(v == 27 || v == 28, "StargazerKernel: invalid signature version");
        address signer = ecrecover(_message, v, r, s);
        require(signer != address(0), "StargazerKernel: invalid signature.");
        return signer;
    }

    function _isKernelMaintainer(address _account) internal view onlyProxy returns (bool) {
        StargazerMemories storage $ = _getStargazerMemory();
        return $.kernelMaintainers[_account].account == _account;
    }

    function _prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}
