// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CryoPod
 * @dev A smart contract that allows each user to create and store a personal pod with a piece of information.
 *      The information is stored permanently on the blockchain, and an event is emitted upon each storage action.
 */
contract CryoPod {
    mapping(address => string) private pods;

    event PodStored(address indexed user, string data);

    /**
     * @dev Stores or updates the caller's pod with the provided data.
     * @param _data The information to be stored in the user's pod.
     */
    function storePod(string memory _data) external {
        pods[msg.sender] = _data;
        emit PodStored(msg.sender, _data);
    }
}
