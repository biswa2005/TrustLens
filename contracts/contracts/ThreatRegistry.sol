// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ThreatRegistry
/// @notice Tamper-evident registry for cryptographic commitments of TrustLens threat reports.
///         Raw URLs, domains, evidence and PII must NEVER be stored here.
contract ThreatRegistry {
    enum Status {
        Pending,
        UnderReview,
        Validated,
        Disputed,
        Revoked
    }

    struct Report {
        bytes32 commitment;
        address reporter;
        uint64 submittedAt;
        uint64 updatedAt;
        uint32 version;
        Status status;
    }

    struct Revision {
        bytes32 commitment;
        uint32 version;
        uint64 timestamp;
    }

    mapping(bytes32 => Report) public reports;
    mapping(bytes32 => Revision[]) private revisions;
    mapping(bytes32 => bytes32[]) private disputes;
    mapping(bytes32 => bool[]) private validations;

    event ReportSubmitted(
        bytes32 indexed reportId,
        bytes32 commitment,
        address indexed reporter,
        uint64 timestamp
    );
    event ReportRevised(
        bytes32 indexed reportId,
        bytes32 newCommitment,
        bytes32 previousCommitment,
        uint32 version,
        uint64 timestamp
    );
    event ReportDisputed(
        bytes32 indexed reportId,
        bytes32 reasonHash,
        address indexed disputant,
        uint64 timestamp
    );
    event ReportValidated(
        bytes32 indexed reportId,
        bool verdict,
        address indexed validator,
        uint64 timestamp
    );
    event ReportRevoked(bytes32 indexed reportId, uint64 timestamp);

    error AlreadyRegistered(bytes32 reportId);
    error NotFound(bytes32 reportId);
    error ZeroCommitment();

    function submitReport(bytes32 reportId, bytes32 commitment) external {
        if (commitment == bytes32(0)) revert ZeroCommitment();
        if (reports[reportId].submittedAt != 0) revert AlreadyRegistered(reportId);

        reports[reportId] = Report({
            commitment: commitment,
            reporter: msg.sender,
            submittedAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp),
            version: 1,
            status: Status.Pending
        });

        revisions[reportId].push(
            Revision({commitment: commitment, version: 1, timestamp: uint64(block.timestamp)})
        );

        emit ReportSubmitted(reportId, commitment, msg.sender, uint64(block.timestamp));
    }

    function reviseReport(bytes32 reportId, bytes32 newCommitment) external {
        if (newCommitment == bytes32(0)) revert ZeroCommitment();
        Report storage r = reports[reportId];
        if (r.submittedAt == 0) revert NotFound(reportId);

        bytes32 prev = r.commitment;
        r.commitment = newCommitment;
        r.updatedAt = uint64(block.timestamp);
        r.version += 1;
        r.status = Status.UnderReview;

        revisions[reportId].push(
            Revision({commitment: newCommitment, version: r.version, timestamp: uint64(block.timestamp)})
        );

        emit ReportRevised(reportId, newCommitment, prev, r.version, uint64(block.timestamp));
    }

    function disputeReport(bytes32 reportId, bytes32 reasonHash) external {
        Report storage r = reports[reportId];
        if (r.submittedAt == 0) revert NotFound(reportId);

        disputes[reportId].push(reasonHash);
        r.status = Status.Disputed;
        r.updatedAt = uint64(block.timestamp);

        emit ReportDisputed(reportId, reasonHash, msg.sender, uint64(block.timestamp));
    }

    function validateReport(bytes32 reportId, bool verdict) external {
        Report storage r = reports[reportId];
        if (r.submittedAt == 0) revert NotFound(reportId);

        validations[reportId].push(verdict);
        r.status = verdict ? Status.Validated : Status.Disputed;
        r.updatedAt = uint64(block.timestamp);

        emit ReportValidated(reportId, verdict, msg.sender, uint64(block.timestamp));
    }

    function revokeReport(bytes32 reportId) external {
        Report storage r = reports[reportId];
        if (r.submittedAt == 0) revert NotFound(reportId);
        r.status = Status.Revoked;
        r.updatedAt = uint64(block.timestamp);
        emit ReportRevoked(reportId, uint64(block.timestamp));
    }

    function getReport(bytes32 reportId)
        external
        view
        returns (
            bytes32 commitment,
            address reporter,
            uint64 submittedAt,
            uint64 updatedAt,
            uint32 version,
            Status status
        )
    {
        Report memory r = reports[reportId];
        if (r.submittedAt == 0) revert NotFound(reportId);
        return (r.commitment, r.reporter, r.submittedAt, r.updatedAt, r.version, r.status);
    }

    function revisionCount(bytes32 reportId) external view returns (uint256) {
        return revisions[reportId].length;
    }

    function getRevision(bytes32 reportId, uint256 index)
        external
        view
        returns (bytes32 commitment, uint32 version, uint64 timestamp)
    {
        Revision memory rev = revisions[reportId][index];
        return (rev.commitment, rev.version, rev.timestamp);
    }
}
