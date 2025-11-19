// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FrontierNFT {
    string public name = "FrontierNFT";
    string public symbol = "FRNT";
    
    uint256 private _tokenId = 1;
    address private _marketplace;
    mapping(uint256 tokenId => address) private _owners;
    mapping(address owner => uint256) private _balances;
    mapping(uint256 tokenId => address) private _tokenApprovals;
    mapping(address owner => mapping(address operator => bool)) private _operatorApprovals;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    modifier onlyMarketplace() {
        require(msg.sender == _marketplace, "FrontierNFT: caller is not authorized");
        _;
    }

    constructor(address marketplace) {
        _marketplace = marketplace;
    }

    function balanceOf(address owner) public view returns (uint256) {
        require(owner != address(0), "FrontierNFT: invalid owner address");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "FrontierNFT: queried owner for nonexistent token");
        return owner;
    }

    function approve(address to, uint256 tokenId) public {
        address owner = ownerOf(tokenId);
        require(msg.sender == owner, "FrontierNFT: approve caller is not the owner");
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function getApproved(uint256 tokenId) public view returns (address) {
        require(_owners[tokenId] != address(0), "FrontierNFT: queried approvals for nonexistent token");
        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) public {
        require(operator != address(0), "FrontierNFT: invalid operator");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) public view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(to != address(0), "FrontierNFT: invalid transfer receiver");
        require(from == ownerOf(tokenId), "FrontierNFT: transfer of token that is not own");
        require(
            msg.sender == from || isApprovedForAll(from, msg.sender) || msg.sender == getApproved(tokenId),
            "FrontierNFT: transfer caller is not owner nor approved"
        );

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function mint(address to) public onlyMarketplace returns (uint256) {
        uint256 currentTokenId = _tokenId;
        _mint(to, currentTokenId);
        return currentTokenId;
    }

    function burn(uint256 tokenId) public onlyMarketplace {
        _burn(tokenId);
    }

    function _mint(address to, uint256 tokenId) internal {
        require(to != address(0), "FrontierNFT: invalid mint receiver");
        require(_owners[tokenId] == address(0), "FrontierNFT: token already minted");

        _balances[to] += 1;
        _owners[tokenId] = to;
        _tokenId += 1;

        emit Transfer(address(0), to, tokenId);
    }

    function _burn(uint256 tokenId) internal {
        address owner = ownerOf(tokenId);
        require(msg.sender == owner, "FrontierNFT: caller is not the owner");
        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Transfer(owner, address(0), tokenId);
    }
}
