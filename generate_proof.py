#!/usr/bin/env python3
"""
PROOF GENERATOR - Real Cryptographic Governance Receipts
=========================================================
Generates verifiable Ed25519-signed receipts with hash chains.
All signatures and hashes are cryptographically valid.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from src.core.receipt import (
    ReceiptGenerator,
    ReceiptSigner,
    OperationPayload,
    ReceiptAction,
    ReceiptChain,
    SignatureAlgorithm
)

def generate_proof_receipts():
    """Generate real cryptographic receipts as proof."""

    print("=" * 70)
    print("JUGGERNAUT RAIL - CRYPTOGRAPHIC RECEIPT PROOF GENERATOR")
    print("=" * 70)
    print()

    # Create signer with real Ed25519 keys
    signer = ReceiptSigner(algorithm=SignatureAlgorithm.ED25519)
    print(f"[KEY] Generated Ed25519 keypair")
    print(f"      Key ID: {signer.key_id}")
    print(f"      Public Key (hex): {signer.get_public_key_bytes().hex()[:64]}...")
    print()

    # Create receipt generator
    generator = ReceiptGenerator(
        signer=signer,
        policy_id="POL-PROOF-V1"
    )

    # Create receipt chain for integrity verification
    chain = ReceiptChain()

    # Sample operations to receipt
    operations = [
        {
            "action": ReceiptAction.QUERY,
            "target": "patient_records",
            "params": {"patient_id": "P-12345", "query_type": "vitals"},
            "agent": "DID:FBT:NURSE:N001"
        },
        {
            "action": ReceiptAction.GENERATE,
            "target": "diagnostic_report",
            "params": {"model": "gpt-4-medical", "confidence_threshold": 0.95},
            "agent": "DID:FBT:AI:DIAG001"
        },
        {
            "action": ReceiptAction.UPDATE,
            "target": "treatment_plan",
            "params": {"plan_id": "TP-789", "modification": "dosage_adjustment"},
            "agent": "DID:FBT:DOCTOR:D042"
        },
        {
            "action": ReceiptAction.REVOKE,
            "target": "data_access",
            "params": {"subject": "P-12345", "revoked_party": "InsuranceCo"},
            "agent": "DID:FBT:PATIENT:P-12345"
        },
        {
            "action": ReceiptAction.INVOKE,
            "target": "ml_inference",
            "params": {"model_id": "risk-assessment-v3", "input_hash": "sha256:abc123"},
            "agent": "DID:FBT:SYSTEM:CORE"
        }
    ]

    receipts = []

    print("-" * 70)
    print("GENERATING RECEIPTS")
    print("-" * 70)

    for i, op_data in enumerate(operations, 1):
        # Create operation payload
        operation = OperationPayload(
            action=op_data["action"],
            target_resource=op_data["target"],
            parameters=op_data["params"],
            agent_id=op_data["agent"]
        )

        # Generate CDT (Consent DNA Token)
        cdt = hashlib.sha3_256(
            f"POLICY:POL-PROOF-V1|EPOCH:1|AGENT:{op_data['agent']}".encode()
        ).hexdigest()[:32]

        # Generate receipt
        receipt = generator.generate(
            operation=operation,
            consent_token=cdt,
            regulatory_mode="HIPAA"
        )

        # Add to chain
        chain.add(receipt)
        receipts.append(receipt)

        print(f"\n[RECEIPT {i}] {receipt.receipt_id}")
        print(f"  Action:     {receipt.action.value}")
        print(f"  Target:     {receipt.target_resource}")
        print(f"  Agent:      {receipt.agent_id}")
        print(f"  Op Hash:    {receipt.operation_hash[:32]}...")
        print(f"  CDT:        {receipt.consent_token}")
        print(f"  Signature:  {receipt.signature[:40]}...")
        print(f"  Chain Seq:  {receipt.chain_sequence}")
        print(f"  Prev Hash:  {receipt.prev_hash[:24]}...")

    print()
    print("-" * 70)
    print("VERIFICATION")
    print("-" * 70)

    # Verify each signature
    print("\n[SIGNATURE VERIFICATION]")
    all_valid = True
    for receipt in receipts:
        signing_data = json.dumps({
            "receipt_id": receipt.receipt_id,
            "timestamp": receipt.timestamp,
            "agent_id": receipt.agent_id,
            "policy_id": receipt.policy_id,
            "operation_hash": receipt.operation_hash,
            "consent_token": receipt.consent_token,
            "chain_sequence": receipt.chain_sequence,
            "prev_hash": receipt.prev_hash,
            "regulatory_mode": receipt.regulatory_mode,
        }, sort_keys=True, separators=(',', ':')).encode('utf-8')

        valid = signer.verify(signing_data, receipt.signature)
        status = "VALID" if valid else "INVALID"
        print(f"  {receipt.receipt_id}: {status}")
        if not valid:
            all_valid = False

    # Verify chain integrity
    print("\n[CHAIN INTEGRITY]")
    is_valid, error = chain.verify_chain_integrity()
    if is_valid:
        print("  Hash chain: VALID")
        print(f"  Chain length: {len(receipts)}")
    else:
        print(f"  Hash chain: BROKEN - {error}")
        all_valid = False

    # Compute Merkle root
    merkle_root = chain.to_merkle_root()
    print(f"  Merkle root: {merkle_root}")

    print()
    print("-" * 70)
    print("EXPORT")
    print("-" * 70)

    # Create proof directory
    proof_dir = Path(__file__).parent / "proof"
    proof_dir.mkdir(exist_ok=True)

    # Export receipts
    receipts_file = proof_dir / "receipts.json"
    with open(receipts_file, 'w') as f:
        json.dump(chain.export(), f, indent=2)
    print(f"\n[SAVED] {receipts_file}")

    # Export verification proof
    proof_file = proof_dir / "verification_proof.json"
    proof_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "Ed25519",
        "key_id": signer.key_id,
        "public_key_hex": signer.get_public_key_bytes().hex(),
        "policy_id": "POL-PROOF-V1",
        "chain_length": len(receipts),
        "merkle_root": merkle_root,
        "all_signatures_valid": all_valid,
        "chain_integrity_valid": is_valid,
        "receipts": [
            {
                "receipt_id": r.receipt_id,
                "operation_hash": r.operation_hash,
                "signature": r.signature,
                "chain_sequence": r.chain_sequence,
            }
            for r in receipts
        ]
    }
    with open(proof_file, 'w') as f:
        json.dump(proof_data, f, indent=2)
    print(f"[SAVED] {proof_file}")

    # Export public key for independent verification
    pubkey_file = proof_dir / "public_key.pem"
    with open(pubkey_file, 'w') as f:
        f.write(signer.get_public_key_pem())
    print(f"[SAVED] {pubkey_file}")

    print()
    print("=" * 70)
    print("PROOF GENERATION COMPLETE")
    print("=" * 70)
    print(f"""
All receipts are cryptographically signed with Ed25519.
Hash chain provides tamper-evidence.
Merkle root enables compact verification.

To verify independently:
  1. Load public_key.pem
  2. For each receipt, reconstruct signing payload
  3. Verify signature using Ed25519
  4. Verify chain by checking prev_hash links
  5. Recompute Merkle root matches

Files saved to: {proof_dir.absolute()}
""")

    return all_valid


if __name__ == "__main__":
    try:
        success = generate_proof_receipts()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
