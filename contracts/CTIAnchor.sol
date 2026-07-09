// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CTIAnchor {

    struct Record {
        bytes32 hash;
        string cid;
        uint256 timestamp;
        string reportId;
    }

    mapping(string => Record) private records;

    address public owner;

    event ReportAnchored(
        string reportId,
        bytes32 hash,
        string cid,
        uint256 timestamp
    );

    constructor() {
        owner = msg.sender;
    }

    function anchorReport(
        string memory reportId,
        bytes32 hash,
        string memory cid
    ) public {

        records[reportId] = Record(
            hash,
            cid,
            block.timestamp,
            reportId
        );

        emit ReportAnchored(
            reportId,
            hash,
            cid,
            block.timestamp
        );
    }

    function verifyReport(
        string memory reportId
    )
        public
        view
        returns (
            bytes32,
            string memory,
            uint256
        )
    {
        Record memory r = records[reportId];

        return (
            r.hash,
            r.cid,
            r.timestamp
        );
    }
}