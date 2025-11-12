// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

contract Voting {
    bytes32 public WinningParty;
    bytes4 private secret;
    uint256 public TargetVotes;
    mapping(address => bool) public UserHasVoted;
    mapping(bytes3 => uint256) public PartyVotes;
    event TargetReached(bytes3 party, string announcement);

    constructor() payable {
        TargetVotes = 150_000_000;
        PartyVotes["BoA"] = 149_999_999;
        PartyVotes["UNZ"] = 1337_1337;
        secret = 0xf00dbabe;
    }

    function publicVote(bytes3 _party, bytes4 _password, bytes3 _voteWeight) public {
            require(PartyVotes[_party] > 0, "Party doesn't exist!");
            uint24 voteWeight = uint24(_voteWeight);
            assembly {
                let pwd := sload(1)
                let cmp := eq(shr(224, _password), pwd)
                switch cmp
                case 1 {
                    mstore(0, caller())
                    mstore(32, UserHasVoted.slot)
                    let hash := keccak256(0, 64)
                    sstore(hash, 0x0)
                }
                default {
                    voteWeight := 1
                }
            }
 
        require(!UserHasVoted[msg.sender], "Already voted!");
        unchecked {
            PartyVotes[_party] += uint24(voteWeight);
        }
        assembly{
            mstore(0, caller())
            mstore(32, UserHasVoted.slot)
            let hash := keccak256(0, 64)
            sstore(hash, 0x1)
        }
        checkWinner(_party);
    }

    function checkWinner(bytes3 _party) public {
        if (PartyVotes[_party] >= TargetVotes) {
            WinningParty = _party;
            emit TargetReached(_party, "won the Elections");
        }
    }
}
