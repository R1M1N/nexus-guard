"""
NEXUS GUARD - Blockchain Audit System
Immutable audit trail and compliance logging using blockchain technology
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import base64

from config import settings, SecurityConstants
from threat_detector import ThreatAnalysis, ThreatSeverity
from response_orchestrator import ResponsePlan

logger = logging.getLogger(__name__)

class AuditEventType(str, Enum):
    """Types of events that require audit logging"""
    THREAT_DETECTED = "THREAT_DETECTED"
    THREAT_ANALYZED = "THREAT_ANALYZED"
    RESPONSE_INITIATED = "RESPONSE_INITIATED"
    RESPONSE_COMPLETED = "RESPONSE_COMPLETED"
    USER_ACCESS = "USER_ACCESS"
    SYSTEM_CONFIGURATION = "SYSTEM_CONFIGURATION"
    COMPLIANCE_CHECK = "COMPLIANCE_CHECK"
    DATA_ACCESS = "DATA_ACCESS"
    PRIVACY_EVENT = "PRIVACY_EVENT"
    FEDERATED_LEARNING = "FEDERATED_LEARNING"
    MODEL_UPDATE = "MODEL_UPDATE"
    THREAT_INTEL_SHARED = "THREAT_INTEL_SHARED"

class BlockStatus(str, Enum):
    """Block validation status"""
    PENDING = "PENDING"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    ORPHANED = "ORPHANED"

@dataclass
class AuditBlock:
    """Individual audit block in the blockchain"""
    block_id: str
    timestamp: datetime
    index: int
    previous_hash: str
    merkle_root: str
    events: List['AuditEvent']
    nonce: int
    hash: str
    validator_id: Optional[str] = None
    status: BlockStatus = BlockStatus.PENDING
    consensus_round: int = 0
    
    def __post_init__(self):
        if not self.hash:
            self.hash = self.calculate_hash()

@dataclass
class AuditEvent:
    """Individual audit event"""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    tenant_id: str
    user_id: Optional[str] = None
    system_id: Optional[str] = None
    event_data: Dict[str, Any] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    risk_level: str = "MEDIUM"
    compliance_flags: List[str] = None
    
    def __post_init__(self):
        if self.compliance_flags is None:
            self.compliance_flags = []
        if self.event_data is None:
            self.event_data = {}

class MerkleTree:
    """Merkle tree for efficient event verification"""
    
    def __init__(self, events: List[AuditEvent]):
        self.events = events
        self.tree = self._build_tree()
        self.root = self.tree[0] if self.tree else ""
    
    def _hash_event(self, event: AuditEvent) -> str:
        """Create hash of an audit event"""
        event_data = {
            'event_id': event.event_id,
            'event_type': event.event_type.value,
            'timestamp': event.timestamp.isoformat(),
            'tenant_id': event.tenant_id,
            'event_data': event.event_data
        }
        
        event_json = json.dumps(event_data, sort_keys=True)
        return hashlib.sha256(event_json.encode()).hexdigest()
    
    def _build_tree(self) -> List[str]:
        """Build Merkle tree from events"""
        if not self.events:
            return [""]
        
        # Create leaf hashes
        leaves = [self._hash_event(event) for event in self.events]
        
        # Build tree upwards
        while len(leaves) > 1:
            next_level = []
            for i in range(0, len(leaves), 2):
                if i + 1 < len(leaves):
                    combined = leaves[i] + leaves[i + 1]
                    next_level.append(hashlib.sha256(combined.encode()).hexdigest())
                else:
                    next_level.append(leaves[i])  # Odd number of leaves
            leaves = next_level
        
        return leaves

class ConsensusEngine:
    """Consensus mechanism for blockchain validation"""
    
    def __init__(self):
        self.validator_nodes = {}
        self.consensus_algorithms = {
            'proof_of_authority': self._proof_of_authority_consensus,
            'practical_byzantine_fault_tolerance': self._pbft_consensus
        }
        self.current_consensus = 'proof_of_authority'
    
    async def validate_block(self, block: AuditBlock) -> bool:
        """Validate a block using consensus mechanism"""
        consensus_method = self.consensus_algorithms.get(self.current_consensus)
        if not consensus_method:
            raise ValueError(f"Unknown consensus algorithm: {self.current_consensus}")
        
        try:
            is_valid = await consensus_method(block)
            
            if is_valid:
                block.status = BlockStatus.VALIDATED
                logger.info(f"Block {block.block_id} validated successfully")
            else:
                block.status = BlockStatus.REJECTED
                logger.warning(f"Block {block.block_id} rejected by consensus")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Error validating block {block.block_id}: {e}")
            block.status = BlockStatus.REJECTED
            return False
    
    async def _proof_of_authority_consensus(self, block: AuditBlock) -> bool:
        """Proof of Authority consensus algorithm"""
        # Get authorized validators
        authorized_validators = await self._get_authorized_validators()
        
        if not authorized_validators:
            logger.warning("No authorized validators available")
            return False
        
        # Simulate validator votes (in real implementation, this would be actual network consensus)
        votes_required = len(authorized_validators) // 2 + 1  # Simple majority
        
        # Mock validation - in reality, this would involve actual validator nodes
        validation_score = await self._simulate_validator_validation(block, authorized_validators)
        
        # Check if validation score meets threshold
        return validation_score >= votes_required
    
    async def _pbft_consensus(self, block: AuditBlock) -> bool:
        """Practical Byzantine Fault Tolerance consensus"""
        # Get all validators (including byzantine ones for testing)
        all_validators = await self._get_all_validators()
        
        # PBFT requires 2f + 1 honest nodes out of 3f + 1 total nodes
        f = len(all_validators) // 3  # Maximum byzantine nodes
        required_votes = 2 * f + 1
        
        # Simulate validation across all validators
        validation_results = await self._simulate_pbft_validation(block, all_validators)
        
        # Count successful validations
        successful_validations = sum(1 for result in validation_results if result)
        
        return successful_validations >= required_votes
    
    async def _get_authorized_validators(self) -> List[str]:
        """Get list of authorized validator nodes"""
        # In a real implementation, this would query a trusted registry
        return ["validator_1", "validator_2", "validator_3"]
    
    async def _get_all_validators(self) -> List[str]:
        """Get all validator nodes (including potential byzantine nodes)"""
        # In a real implementation, this would get all network participants
        return ["validator_1", "validator_2", "validator_3", "validator_4"]
    
    async def _simulate_validator_validation(self, block: AuditBlock, validators: List[str]) -> int:
        """Simulate validation by authorized validators"""
        # Mock validation - in reality, this would be actual cryptographic validation
        successful_validations = 0
        
        for validator in validators:
            # Simulate validation with 90% success rate
            if hash(block.block_id + validator)[0] % 10 < 9:
                successful_validations += 1
        
        return successful_validations
    
    async def _simulate_pbft_validation(self, block: AuditBlock, validators: List[str]) -> List[bool]:
        """Simulate PBFT validation across all validators"""
        results = []
        
        for validator in validators:
            # Simulate validation with 85% success rate for honest nodes
            if hash(block.block_id + validator)[0] % 20 < 17:  # 85% success rate
                results.append(True)
            else:
                results.append(False)
        
        return results

class SmartContractEngine:
    """Smart contract execution for automated compliance and responses"""
    
    def __init__(self):
        self.contracts = {
            'high_severity_response': self._high_severity_response_contract,
            'compliance_check': self._compliance_check_contract,
            'data_retention': self._data_retention_contract,
            'privacy_violation': self._privacy_violation_contract
        }
    
    async def execute_contract(self, contract_name: str, event: AuditEvent) -> Dict[str, Any]:
        """Execute a smart contract"""
        contract = self.contracts.get(contract_name)
        if not contract:
            raise ValueError(f"Unknown contract: {contract_name}")
        
        try:
            result = await contract(event)
            logger.info(f"Executed contract {contract_name} for event {event.event_id}")
            return result
        except Exception as e:
            logger.error(f"Error executing contract {contract_name}: {e}")
            return {"error": str(e)}
    
    async def _high_severity_response_contract(self, event: AuditEvent) -> Dict[str, Any]:
        """Smart contract for high-severity threat response"""
        if event.risk_level in ['CRITICAL', 'HIGH']:
            # Automatically trigger response actions
            return {
                "contract_executed": True,
                "actions_required": [
                    "IMMEDIATE_ISOLATION",
                    "ESCALATE_TO_CISO",
                    "PRESERVE_FORENSICS"
                ],
                "contract_type": "high_severity_response",
                "execution_timestamp": datetime.utcnow().isoformat()
            }
        return {"contract_executed": False, "reason": "Risk level not sufficient"}
    
    async def _compliance_check_contract(self, event: AuditEvent) -> Dict[str, Any]:
        """Smart contract for compliance checking"""
        compliance_violations = []
        
        # Check GDPR compliance
        if 'GDPR' in event.compliance_flags:
            if event.event_type == AuditEventType.DATA_ACCESS:
                if not event.event_data.get('consent_verified', False):
                    compliance_violations.append("GDPR_CONSENT_NOT_VERIFIED")
            
            if event.event_type == AuditEventType.PRIVACY_EVENT:
                compliance_violations.append("GDPR_PRIVACY_VIOLATION_DETECTED")
        
        # Check HIPAA compliance
        if 'HIPAA' in event.compliance_flags:
            if 'healthcare' in event.event_data.get('data_classification', '').lower():
                if event.event_type == AuditEventType.DATA_ACCESS:
                    if not event.user_id:  # No user ID means potential violation
                        compliance_violations.append("HIPAA_ACCESS_WITHOUT_AUTHENTICATION")
        
        return {
            "contract_executed": True,
            "compliance_violations": compliance_violations,
            "requires_investigation": len(compliance_violations) > 0,
            "contract_type": "compliance_check"
        }
    
    async def _data_retention_contract(self, event: AuditEvent) -> Dict[str, Any]:
        """Smart contract for data retention policies"""
        if event.event_type == AuditEventType.DATA_ACCESS:
            retention_period = event.event_data.get('retention_period_days', 2555)  # Default 7 years
            
            return {
                "contract_executed": True,
                "retention_period_days": retention_period,
                "deletion_date": (datetime.utcnow() + timedelta(days=retention_period)).isoformat(),
                "contract_type": "data_retention"
            }
        return {"contract_executed": False, "reason": "Not a data access event"}
    
    async def _privacy_violation_contract(self, event: AuditEvent) -> Dict[str, Any]:
        """Smart contract for privacy violation response"""
        if event.event_type == AuditEventType.PRIVACY_EVENT:
            return {
                "contract_executed": True,
                "actions_required": [
                    "INVESTIGATE_VIOLATION",
                    "NOTIFY_DATA_PROTECTION_OFFICER",
                    "ASSESS_DATA_SUBJECT_IMPACT"
                ],
                "contract_type": "privacy_violation",
                "severity": event.risk_level
            }
        return {"contract_executed": False, "reason": "Not a privacy event"}

class BlockchainAuditSystem:
    """Main blockchain audit system"""
    
    def __init__(self):
        self.chain = []
        self.pending_events = []
        self.merkle_tree = None
        self.consensus_engine = ConsensusEngine()
        self.smart_contract_engine = SmartContractEngine()
        self.block_size_limit = 100  # Maximum events per block
        self.consensus_threshold = 0.8  # 80% consensus required
        self.private_key = None
        self.public_key = None
        
        # Initialize cryptographic keys
        self._initialize_keys()
        
        # Create genesis block
        self._create_genesis_block()
    
    def _initialize_keys(self):
        """Initialize cryptographic keys for signing"""
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
            
            # Store public key as string
            self.public_key_pem = self.public_key.public_key_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error initializing cryptographic keys: {e}")
            raise
    
    def _create_genesis_block(self):
        """Create the genesis block"""
        genesis_event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.SYSTEM_CONFIGURATION,
            timestamp=datetime.utcnow(),
            tenant_id="system",
            event_data={
                "blockchain_initialized": True,
                "version": "2.0.0",
                "consensus_algorithm": "proof_of_authority"
            }
        )
        
        genesis_block = AuditBlock(
            block_id="genesis_0",
            timestamp=datetime.utcnow(),
            index=0,
            previous_hash="0",
            merkle_root="",
            events=[genesis_event],
            nonce=0,
            hash="",
            status=BlockStatus.VALIDATED
        )
        
        self.chain.append(genesis_block)
        logger.info("Created genesis block")
    
    def calculate_hash(self, block: AuditBlock) -> str:
        """Calculate hash for a block"""
        block_data = {
            'index': block.index,
            'timestamp': block.timestamp.isoformat(),
            'previous_hash': block.previous_hash,
            'merkle_root': block.merkle_root,
            'nonce': block.nonce
        }
        
        block_json = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_json.encode()).hexdigest()
    
    async def log_audit_event(self, event: AuditEvent) -> bool:
        """Log an audit event to the blockchain"""
        try:
            # Add event to pending events
            self.pending_events.append(event)
            
            # Execute relevant smart contracts
            await self._execute_relevant_contracts(event)
            
            # Create block if we have enough events or time
            if len(self.pending_events) >= self.block_size_limit or await self._should_create_block():
                await self._create_block()
            
            logger.info(f"Logged audit event {event.event_id} of type {event.event_type.value}")
            return True
            
        except Exception as e:
            logger.error(f"Error logging audit event {event.event_id}: {e}")
            return False
    
    async def _execute_relevant_contracts(self, event: AuditEvent):
        """Execute relevant smart contracts for the event"""
        contract_mapping = {
            AuditEventType.THREAT_DETECTED: ['high_severity_response'],
            AuditEventType.COMPLIANCE_CHECK: ['compliance_check'],
            AuditEventType.DATA_ACCESS: ['data_retention'],
            AuditEventType.PRIVACY_EVENT: ['privacy_violation', 'compliance_check']
        }
        
        applicable_contracts = contract_mapping.get(event.event_type, [])
        
        for contract_name in applicable_contracts:
            try:
                result = await self.smart_contract_engine.execute_contract(contract_name, event)
                
                # Log contract execution results
                await self._log_contract_execution(contract_name, event, result)
                
            except Exception as e:
                logger.error(f"Error executing contract {contract_name} for event {event.event_id}: {e}")
    
    async def _log_contract_execution(self, contract_name: str, event: AuditEvent, result: Dict[str, Any]):
        """Log smart contract execution results"""
        contract_event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.SYSTEM_CONFIGURATION,
            timestamp=datetime.utcnow(),
            tenant_id=event.tenant_id,
            event_data={
                "contract_name": contract_name,
                "original_event_id": event.event_id,
                "contract_result": result,
                "execution_type": "smart_contract"
            }
        )
        
        self.pending_events.append(contract_event)
    
    async def _should_create_block(self) -> bool:
        """Determine if we should create a new block"""
        if not self.pending_events:
            return False
        
        # Create block if the oldest event is older than 5 minutes
        oldest_event = min(self.pending_events, key=lambda e: e.timestamp)
        age = datetime.utcnow() - oldest_event.timestamp
        
        return age > timedelta(minutes=5)
    
    async def _create_block(self):
        """Create a new block with pending events"""
        if not self.pending_events:
            return
        
        # Create Merkle tree from pending events
        self.merkle_tree = MerkleTree(self.pending_events)
        
        # Get previous block hash
        previous_block = self.chain[-1] if self.chain else None
        previous_hash = previous_block.hash if previous_block else "0"
        
        # Create new block
        block = AuditBlock(
            block_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            index=len(self.chain),
            previous_hash=previous_hash,
            merkle_root=self.merkle_tree.root,
            events=self.pending_events.copy(),
            nonce=0,
            hash="",
            status=BlockStatus.PENDING
        )
        
        # Add block to chain
        self.chain.append(block)
        
        # Clear pending events
        self.pending_events.clear()
        
        # Validate block using consensus
        is_valid = await self.consensus_engine.validate_block(block)
        
        if is_valid:
            logger.info(f"Created and validated block {block.block_id} with {len(block.events)} events")
        else:
            logger.warning(f"Created block {block.block_id} but failed validation")
        
        # Sign the block
        await self._sign_block(block)
    
    async def _sign_block(self, block: AuditBlock):
        """Sign a block with our private key"""
        try:
            # Create signature of block hash
            signature = self.private_key.sign(
                block.hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Add signature to block (in a real implementation, this would be stored separately)
            block.validation_signature = base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error signing block {block.block_id}: {e}")
    
    async def verify_block_integrity(self, block_id: str) -> Dict[str, Any]:
        """Verify the integrity of a specific block"""
        block = next((b for b in self.chain if b.block_id == block_id), None)
        if not block:
            return {"valid": False, "reason": "Block not found"}
        
        # Verify hash
        calculated_hash = self.calculate_hash(block)
        if calculated_hash != block.hash:
            return {"valid": False, "reason": "Hash mismatch"}
        
        # Verify Merkle tree
        merkle_tree = MerkleTree(block.events)
        if merkle_tree.root != block.merkle_root:
            return {"valid": False, "reason": "Merkle root mismatch"}
        
        # Verify chain continuity
        if block.index > 0:
            previous_block = self.chain[block.index - 1]
            if block.previous_hash != previous_block.hash:
                return {"valid": False, "reason": "Chain discontinuity"}
        
        return {
            "valid": True,
            "block_id": block_id,
            "index": block.index,
            "hash_verified": True,
            "merkle_verified": True,
            "chain_verified": True,
            "consensus_status": block.status.value
        }
    
    async def get_audit_trail(self, tenant_id: str, start_date: datetime = None, 
                            end_date: datetime = None) -> List[Dict[str, Any]]:
        """Get audit trail for a specific tenant"""
        events = []
        
        for block in self.chain:
            for event in block.events:
                if event.tenant_id == tenant_id:
                    # Apply date filters
                    if start_date and event.timestamp < start_date:
                        continue
                    if end_date and event.timestamp > end_date:
                        continue
                    
                    events.append({
                        "block_id": block.block_id,
                        "event_id": event.event_id,
                        "event_type": event.event_type.value,
                        "timestamp": event.timestamp.isoformat(),
                        "user_id": event.user_id,
                        "risk_level": event.risk_level,
                        "compliance_flags": event.compliance_flags,
                        "block_status": block.status.value
                    })
        
        return sorted(events, key=lambda e: e["timestamp"])
    
    async def get_compliance_report(self, regulation: str) -> Dict[str, Any]:
        """Generate compliance report for specific regulation"""
        compliance_events = []
        
        for block in self.chain:
            for event in block.events:
                if regulation in event.compliance_flags:
                    compliance_events.append({
                        "event_id": event.event_id,
                        "timestamp": event.timestamp.isoformat(),
                        "event_type": event.event_type.value,
                        "compliance_flag": regulation,
                        "risk_level": event.risk_level
                    })
        
        # Analyze compliance patterns
        high_risk_events = [e for e in compliance_events if e["risk_level"] in ["HIGH", "CRITICAL"]]
        
        return {
            "regulation": regulation,
            "total_compliance_events": len(compliance_events),
            "high_risk_events": len(high_risk_events),
            "compliance_score": max(0, 1.0 - (len(high_risk_events) / max(1, len(compliance_events)))),
            "events": compliance_events,
            "report_generated": datetime.utcnow().isoformat()
        }
    
    async def get_blockchain_statistics(self) -> Dict[str, Any]:
        """Get comprehensive blockchain statistics"""
        total_blocks = len(self.chain)
        total_events = sum(len(block.events) for block in self.chain)
        pending_events = len(self.pending_events)
        
        # Block status distribution
        status_counts = {}
        for block in self.chain:
            status = block.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Event type distribution
        event_type_counts = {}
        for block in self.chain:
            for event in block.events:
                event_type = event.event_type.value
                event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        
        # Chain integrity
        valid_blocks = sum(1 for block in self.chain if block.status == BlockStatus.VALIDATED)
        integrity_score = valid_blocks / total_blocks if total_blocks > 0 else 0
        
        return {
            "total_blocks": total_blocks,
            "total_events": total_events,
            "pending_events": pending_events,
            "block_status_distribution": status_counts,
            "event_type_distribution": event_type_counts,
            "chain_integrity_score": integrity_score,
            "average_events_per_block": total_events / max(1, total_blocks),
            "blockchain_size_estimate_mb": total_blocks * 0.1,  # Estimated
            "last_block_timestamp": self.chain[-1].timestamp.isoformat() if self.chain else None
        }

# Global blockchain audit system instance
blockchain_audit_system = BlockchainAuditSystem()