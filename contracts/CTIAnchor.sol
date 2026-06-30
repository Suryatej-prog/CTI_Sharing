// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CTIAnchor {
    
    struct Record {
        bytes32 hash;
        uint256 timestamp;
        string reportId;
    }

    mapping(string => Record) private records;
    address public owner;

    event HashAnchored(string reportId, bytes32 hash, uint256 timestamp);

    constructor() {
        owner = msg.sender;
    }

    function anchorHash(string memory reportId, bytes32 hash) public {
        records[reportId] = Record(hash, block.timestamp, reportId);
        emit HashAnchored(reportId, hash, block.timestamp);
    }

    function verifyHash(string memory reportId) public view returns (bytes32, uint256) {
        Record memory r = records[reportId];
        return (r.hash, r.timestamp);
    }
}