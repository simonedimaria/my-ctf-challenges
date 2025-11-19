// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/***
    __  __     ___            ____  _______  __
   / / / /__  / (_)___  _____/ __ \/ ____/ |/ /
  / /_/ / _ \/ / / __ \/ ___/ / / / __/  |   / 
 / __  /  __/ / / /_/ (__  ) /_/ / /___ /   |  
/_/ /_/\___/_/_/\____/____/_____/_____//_/|_|  
                                               
    Today's item listing:
    * Eldorion Fang (ELD): A shard of a Eldorion's fang, said to imbue the holder with courage and the strength of the ancient beast. A symbol of valor in battle.
    * Malakar Essence (MAL): A dark, viscous substance, pulsing with the corrupted power of Malakar. Use with extreme caution, as it whispers promises of forbidden strength. MAY CAUSE HALLUCINATIONS.
    * Helios Lumina Shards (HLS): Fragments of pure, solidified light, radiating the warmth and energy of Helios. These shards are key to powering Eldoria's invisible eye.
***/

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

contract EldorionFang is ERC20 {
    constructor(uint256 initialSupply) ERC20("EldorionFang", "ELD") {
        _mint(msg.sender, initialSupply);
    }
}

contract MalakarEssence is ERC20 {
    constructor(uint256 initialSupply) ERC20("MalakarEssence", "MAL") {
        _mint(msg.sender, initialSupply);
    }
}

contract HeliosLuminaShards is ERC20 {
    constructor(uint256 initialSupply) ERC20("HeliosLuminaShards", "HLS") {
        _mint(msg.sender, initialSupply);
    }
}

contract HeliosDEX {
    EldorionFang public eldorionFang;
    MalakarEssence public malakarEssence;
    HeliosLuminaShards public heliosLuminaShards;

    uint256 public reserveELD;
    uint256 public reserveMAL;
    uint256 public reserveHLS;
    
    uint256 public immutable exchangeRatioELD = 2;
    uint256 public immutable exchangeRatioMAL = 4;
    uint256 public immutable exchangeRatioHLS = 10;

    uint256 public immutable feeBps = 25;

    mapping(address => bool) public hasRefunded;

    bool public _tradeLock = false;
    
    event HeliosBarter(address item, uint256 inAmount, uint256 outAmount);
    event HeliosRefund(address item, uint256 inAmount, uint256 ethOut);

    constructor(uint256 initialSupplies) payable {
        eldorionFang = new EldorionFang(initialSupplies);
        malakarEssence = new MalakarEssence(initialSupplies);
        heliosLuminaShards = new HeliosLuminaShards(initialSupplies);
        reserveELD = initialSupplies;
        reserveMAL = initialSupplies;
        reserveHLS = initialSupplies;
    }

    modifier underHeliosEye {
        require(msg.value > 0, "HeliosDEX: Helios sees your empty hand! Only true offerings are worthy of a HeliosBarter");
        _;
    }

    modifier heliosGuardedTrade() {
        require(_tradeLock != true, "HeliosDEX: Helios shields this trade! Another transaction is already underway. Patience, traveler");
        _tradeLock = true;
        _;
        _tradeLock = false;
    }

    function swapForELD() external payable underHeliosEye {
        uint256 grossELD = Math.mulDiv(msg.value, exchangeRatioELD, 1e18, Math.Rounding(0));
        uint256 fee = (grossELD * feeBps) / 10_000;
        uint256 netELD = grossELD - fee;

        require(netELD <= reserveELD, "HeliosDEX: Helios grieves that the ELD reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");

        reserveELD -= netELD;
        eldorionFang.transfer(msg.sender, netELD);

        emit HeliosBarter(address(eldorionFang), msg.value, netELD);
    }

    function swapForMAL() external payable underHeliosEye {
        uint256 grossMal = Math.mulDiv(msg.value, exchangeRatioMAL, 1e18, Math.Rounding(1));
        uint256 fee = (grossMal * feeBps) / 10_000;
        uint256 netMal = grossMal - fee;

        require(netMal <= reserveMAL, "HeliosDEX: Helios grieves that the MAL reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");

        reserveMAL -= netMal;
        malakarEssence.transfer(msg.sender, netMal);

        emit HeliosBarter(address(malakarEssence), msg.value, netMal);
    }

    function swapForHLS() external payable underHeliosEye {
        uint256 grossHLS = Math.mulDiv(msg.value, exchangeRatioHLS, 1e18, Math.Rounding(3));
        uint256 fee = (grossHLS * feeBps) / 10_000;
        uint256 netHLS = grossHLS - fee;
        
        require(netHLS <= reserveHLS, "HeliosDEX: Helios grieves that the HSL reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");
        

        reserveHLS -= netHLS;
        heliosLuminaShards.transfer(msg.sender, netHLS);

        emit HeliosBarter(address(heliosLuminaShards), msg.value, netHLS);
    }

    function oneTimeRefund(address item, uint256 amount) external heliosGuardedTrade {
        require(!hasRefunded[msg.sender], "HeliosDEX: refund already bestowed upon thee");
        require(amount > 0, "HeliosDEX: naught for naught is no trade. Offer substance, or be gone!");

        uint256 exchangeRatio;
        
        if (item == address(eldorionFang)) {
            exchangeRatio = exchangeRatioELD;
            require(eldorionFang.transferFrom(msg.sender, address(this), amount), "ELD transfer failed");
            reserveELD += amount;
        } else if (item == address(malakarEssence)) {
            exchangeRatio = exchangeRatioMAL;
            require(malakarEssence.transferFrom(msg.sender, address(this), amount), "MAL transfer failed");
            reserveMAL += amount;
        } else if (item == address(heliosLuminaShards)) {
            exchangeRatio = exchangeRatioHLS;
            require(heliosLuminaShards.transferFrom(msg.sender, address(this), amount), "HLS transfer failed");
            reserveHLS += amount;
        } else {
            revert("HeliosDEX: Helios descries forbidden offering");
        }

        uint256 grossEth = Math.mulDiv(amount, 1e18, exchangeRatio);

        uint256 fee = (grossEth * feeBps) / 10_000;
        uint256 netEth = grossEth - fee;

        hasRefunded[msg.sender] = true;
        payable(msg.sender).transfer(netEth);
        
        emit HeliosRefund(item, amount, netEth);
    }
}
