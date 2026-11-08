import os
import json
from typing import Any

from web3 import Web3

MINIMAL_ABI = [
    {"inputs":[{"name":"reportId","type":"bytes32"},{"name":"commitment","type":"bytes32"}],"name":"submitReport","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"reportId","type":"bytes32"},{"name":"newCommitment","type":"bytes32"}],"name":"reviseReport","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"reportId","type":"bytes32"},{"name":"reasonHash","type":"bytes32"}],"name":"disputeReport","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"reportId","type":"bytes32"},{"name":"verdict","type":"bool"}],"name":"validateReport","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"reportId","type":"bytes32"}],"name":"revokeReport","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"reportId","type":"bytes32"}],"name":"getReport","outputs":[{"name":"commitment","type":"bytes32"},{"name":"reporter","type":"address"},{"name":"submittedAt","type":"uint64"},{"name":"updatedAt","type":"uint64"},{"name":"version","type":"uint32"},{"name":"status","type":"uint8"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"name":"reportId","type":"bytes32"}],"name":"revisionCount","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"name":"reportId","type":"bytes32"},{"name":"index","type":"uint256"}],"name":"getRevision","outputs":[{"name":"commitment","type":"bytes32"},{"name":"version","type":"uint32"},{"name":"timestamp","type":"uint64"}],"stateMutability":"view","type":"function"},
]


class ChainClient:
    def __init__(self):
        self.rpc_url = os.getenv("CHAIN_RPC_URL", "http://127.0.0.1:8545")
        self.contract_address = os.getenv("CONTRACT_ADDRESS")
        self.private_key = os.getenv("PRIVATE_KEY")
        self.chain_id = int(os.getenv("CHAIN_ID", "31337"))

        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        if not self.w3.is_connected():
            raise RuntimeError(f"Cannot connect to chain at {self.rpc_url}")

        if not self.contract_address:
            raise RuntimeError("CONTRACT_ADDRESS not set")
        # Load ABI if artifact exists, else minimal
        abi = MINIMAL_ABI
        artifact_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "contracts",
            "artifacts",
            "contracts",
            "ThreatRegistry.sol",
            "ThreatRegistry.json",
        )
        if os.path.exists(artifact_path):
            with open(artifact_path) as f:
                artifact = json.load(f)
                abi = artifact.get("abi", abi)

        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.contract_address), abi=abi
        )

        if self.private_key:
            self.account = self.w3.eth.account.from_key(self.private_key)
            self.sender = self.account.address
        else:
            self.account = None
            self.sender = None

    def _send(self, fn) -> dict:
        if not self.account:
            raise RuntimeError("PRIVATE_KEY not configured")
        tx = fn.build_transaction(
            {
                "from": self.sender,
                "nonce": self.w3.eth.get_transaction_count(self.sender),
                "chainId": self.chain_id,
                "gas": 1000000,
                "gasPrice": self.w3.eth.gas_price,
            }
        )
        signed = self.w3.eth.account.sign_transaction(tx, self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        return {
            "tx_hash": tx_hash.hex(),
            "block_number": receipt.blockNumber,
        }

    def submit_report(self, report_id_hex: str, commitment_hex: str) -> dict:
        report_id = bytes.fromhex(report_id_hex.replace("0x", "").zfill(64))
        commitment = bytes.fromhex(commitment_hex.replace("0x", "").zfill(64))
        fn = self.contract.functions.submitReport(report_id, commitment)
        return self._send(fn)

    def revise_report(self, report_id_hex: str, new_commitment_hex: str) -> dict:
        report_id = bytes.fromhex(report_id_hex.replace("0x", "").zfill(64))
        commitment = bytes.fromhex(new_commitment_hex.replace("0x", "").zfill(64))
        fn = self.contract.functions.reviseReport(report_id, commitment)
        return self._send(fn)

    def dispute_report(self, report_id_hex: str, reason_hash_hex: str) -> dict:
        report_id = bytes.fromhex(report_id_hex.replace("0x", "").zfill(64))
        reason = bytes.fromhex(reason_hash_hex.replace("0x", "").zfill(64))
        fn = self.contract.functions.disputeReport(report_id, reason)
        return self._send(fn)

    def validate_report(self, report_id_hex: str, verdict: bool) -> dict:
        report_id = bytes.fromhex(report_id_hex.replace("0x", "").zfill(64))
        fn = self.contract.functions.validateReport(report_id, verdict)
        return self._send(fn)

    def fetch_commitment(self, report_id_hex: str) -> str:
        report_id = bytes.fromhex(report_id_hex.replace("0x", "").zfill(64))
        result = self.contract.functions.getReport(report_id).call()
        return result[0].hex()

    def fetch_status(self, report_id_hex: str) -> int:
        report_id = bytes.fromhex(report_id_hex.replace("0x", "").zfill(64))
        result = self.contract.functions.getReport(report_id).call()
        return result[5]

    def fetch_revision_count(self, report_id_hex: str) -> int:
        report_id = bytes.fromhex(report_id_hex.replace("0x", "").zfill(64))
        return self.contract.functions.revisionCount(report_id).call()

    def fetch_revision(self, report_id_hex: str, index: int) -> dict:
        report_id = bytes.fromhex(report_id_hex.replace("0x", "").zfill(64))
        result = self.contract.functions.getRevision(report_id, index).call()
        return {
            "commitment": result[0].hex(),
            "version": result[1],
            "timestamp": result[2],
        }
    def is_connected(self) -> bool:
        return self.w3.is_connected()
