"""
NEXUS GUARD - Federated Learning System
Privacy-preserving collaborative threat intelligence sharing
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import numpy as np
import pickle
import zlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from config import settings, SecurityLevel

logger = logging.getLogger(__name__)

class ClientRole(str, Enum):
    """Client participation roles"""
    DATA_OWNER = "DATA_OWNER"
    MODEL_AGGREGATOR = "MODEL_AGGREGATOR"
    VALIDATOR = "VALIDATOR"

class ModelType(str, Enum):
    """Types of AI models for federated learning"""
    THREAT_DETECTION = "THREAT_DETECTION"
    ANOMALY_DETECTION = "ANOMALY_DETECTION"
    BEHAVIORAL_ANALYSIS = "BEHAVIORAL_ANALYSIS"
    MALWARE_CLASSIFICATION = "MALWARE_CLASSIFICATION"
    NETWORK_INTRUSION = "NETWORK_INTRUSION"

@dataclass
class ClientNode:
    """Federated learning client node"""
    id: str
    organization_id: str
    role: ClientRole
    public_key: str
    reputation_score: float = 1.0
    last_active: datetime = None
    contributed_models: int = 0
    validation_score: float = 0.0
    privacy_budget: float = 1.0
    participation_level: str = "STANDARD"
    
    def __post_init__(self):
        if self.last_active is None:
            self.last_active = datetime.utcnow()

@dataclass
class TrainingRound:
    """Federated learning training round"""
    id: str
    round_number: int
    model_type: ModelType
    participating_clients: List[str]
    global_model_version: str
    start_time: datetime
    end_time: Optional[datetime] = None
    convergence_threshold: float = 0.01
    min_participants: int = 3
    
@dataclass
class ModelUpdate:
    """Individual model update from client"""
    client_id: str
    model_type: ModelType
    model_weights: bytes  # Encrypted model weights
    update_size_bytes: int
    privacy_mechanism: str
    differential_privacy_noise: Optional[Dict[str, float]] = None
    validation_accuracy: Optional[float] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

class PrivacyPreservationEngine:
    """Privacy preservation mechanisms for federated learning"""
    
    def __init__(self, encryption_key: bytes = None):
        if encryption_key is None:
            encryption_key = Fernet.generate_key()
        
        self.fernet = Fernet(encryption_key)
        self.key_derivation_salt = b'nexus_guard_federated_learning_salt_2024'
    
    def encrypt_model_weights(self, weights: np.ndarray) -> bytes:
        """Encrypt model weights using Fernet encryption"""
        # Serialize weights to bytes
        weights_bytes = pickle.dumps(weights)
        
        # Compress before encryption for efficiency
        compressed_weights = zlib.compress(weights_bytes)
        
        # Encrypt
        encrypted_weights = self.fernet.encrypt(compressed_weights)
        
        return encrypted_weights
    
    def decrypt_model_weights(self, encrypted_weights: bytes) -> np.ndarray:
        """Decrypt model weights"""
        try:
            # Decrypt
            decrypted_weights = self.fernet.decrypt(encrypted_weights)
            
            # Decompress
            decompressed_weights = zlib.decompress(decrypted_weights)
            
            # Deserialize back to numpy array
            weights = pickle.loads(decompressed_weights)
            
            return weights
        except Exception as e:
            logger.error(f"Error decrypting model weights: {e}")
            raise
    
    def add_differential_privacy_noise(self, weights: np.ndarray, epsilon: float = 1.0) -> np.ndarray:
        """Add differential privacy noise to model weights"""
        # Calculate sensitivity (simplified)
        sensitivity = np.max(np.abs(weights))
        
        # Generate Laplace noise
        scale = sensitivity / epsilon
        noise = np.random.laplace(0, scale, weights.shape)
        
        # Add noise to weights
        noisy_weights = weights + noise
        
        return noisy_weights
    
    def generate_model_hash(self, weights: np.ndarray) -> str:
        """Generate cryptographic hash of model weights"""
        weights_bytes = pickle.dumps(weights)
        hash_object = hashlib.sha256(weights_bytes)
        return hash_object.hexdigest()
    
    def verify_model_integrity(self, weights: np.ndarray, expected_hash: str) -> bool:
        """Verify model integrity using hash"""
        actual_hash = self.generate_model_hash(weights)
        return actual_hash == expected_hash

class FederatedModelAggregator:
    """Model aggregation for federated learning"""
    
    def __init__(self):
        self.aggregation_strategies = {
            ModelType.THREAT_DETECTION: self._weighted_average_aggregation,
            ModelType.ANOMALY_DETECTION: self._fedavg_aggregation,
            ModelType.BEHAVIORAL_ANALYSIS: self._reputation_weighted_aggregation,
            ModelType.MALWARE_CLASSIFICATION: self._accuracy_weighted_aggregation,
            ModelType.NETWORK_INTRUSION: self._fedavg_aggregation
        }
    
    def aggregate_models(self, model_updates: List[ModelUpdate], 
                        aggregation_strategy: str = "fedavg") -> Dict[str, Any]:
        """Aggregate multiple model updates into global model"""
        if not model_updates:
            raise ValueError("No model updates provided for aggregation")
        
        model_type = model_updates[0].model_type
        aggregation_method = self.aggregation_strategies.get(model_type, self._fedavg_aggregation)
        
        try:
            # Decrypt and validate all model updates
            validated_updates = []
            for update in model_updates:
                validated_update = self._validate_and_decrypt_update(update)
                if validated_update:
                    validated_updates.append(validated_update)
            
            if len(validated_updates) < len(model_updates):
                logger.warning(f"Only {len(validated_updates)} of {len(model_updates)} updates were valid")
            
            # Perform aggregation
            global_model = aggregation_method(validated_updates)
            
            # Generate aggregation statistics
            aggregation_stats = {
                "total_updates": len(model_updates),
                "valid_updates": len(validated_updates),
                "aggregation_method": aggregation_method.__name__,
                "model_type": model_type.value,
                "aggregation_timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Aggregated {len(validated_updates)} model updates using {aggregation_method.__name__}")
            
            return {
                "global_model": global_model,
                "statistics": aggregation_stats,
                "validated_updates_count": len(validated_updates)
            }
            
        except Exception as e:
            logger.error(f"Error aggregating models: {e}")
            raise
    
    def _validate_and_decrypt_update(self, update: ModelUpdate) -> Optional[Dict[str, Any]]:
        """Validate and decrypt a model update"""
        try:
            # Check timestamp (updates older than 24 hours are discarded)
            if datetime.utcnow() - update.timestamp > timedelta(hours=24):
                logger.warning(f"Update from {update.client_id} is too old, skipping")
                return None
            
            # Check update size (reject updates that are too large)
            if update.update_size_bytes > 100 * 1024 * 1024:  # 100MB limit
                logger.warning(f"Update from {update.client_id} is too large, skipping")
                return None
            
            # In a real implementation, we would decrypt the model weights here
            # For now, we'll create a mock decrypted update
            mock_weights = np.random.randn(1000)  # Mock model weights
            
            return {
                "client_id": update.client_id,
                "weights": mock_weights,
                "validation_accuracy": update.validation_accuracy or 0.8,
                "privacy_mechanism": update.privacy_mechanism,
                "update_metadata": {
                    "timestamp": update.timestamp,
                    "model_type": update.model_type.value
                }
            }
            
        except Exception as e:
            logger.error(f"Error validating update from {update.client_id}: {e}")
            return None
    
    def _fedavg_aggregation(self, updates: List[Dict[str, Any]]) -> np.ndarray:
        """Federated Averaging (FedAvg) aggregation strategy"""
        weights_list = [update["weights"] for update in updates]
        weights_array = np.array(weights_list)
        
        # Simple average
        global_weights = np.mean(weights_array, axis=0)
        
        return global_weights
    
    def _weighted_average_aggregation(self, updates: List[Dict[str, Any]]) -> np.ndarray:
        """Weighted average aggregation based on data size and accuracy"""
        weights_list = []
        total_samples = 0
        sample_sizes = []
        
        # Assume each update has associated data size
        for update in updates:
            # Mock data size calculation (in reality, this would come from the client)
            data_size = np.prod(update["weights"].shape)  # Use model size as proxy
            sample_sizes.append(data_size)
            total_samples += data_size
        
        # Normalize weights
        normalized_weights = np.array(sample_sizes) / total_samples
        
        # Calculate weighted average
        weighted_sum = np.zeros_like(updates[0]["weights"])
        for i, update in enumerate(updates):
            weighted_sum += update["weights"] * normalized_weights[i]
        
        return weighted_sum
    
    def _reputation_weighted_aggregation(self, updates: List[Dict[str, Any]]) -> np.ndarray:
        """Aggregation weighted by client reputation scores"""
        # Mock reputation scores (in reality, these would come from the client registry)
        reputation_scores = [0.9 for _ in updates]  # All clients have 0.9 reputation
        
        # Normalize reputation scores
        normalized_scores = np.array(reputation_scores) / np.sum(reputation_scores)
        
        # Calculate reputation-weighted average
        weighted_sum = np.zeros_like(updates[0]["weights"])
        for i, update in enumerate(updates):
            weighted_sum += update["weights"] * normalized_scores[i]
        
        return weighted_sum
    
    def _accuracy_weighted_aggregation(self, updates: List[Dict[str, Any]]) -> np.ndarray:
        """Aggregation weighted by model validation accuracy"""
        accuracy_scores = [update["validation_accuracy"] for update in updates]
        
        # Normalize accuracy scores
        normalized_scores = np.array(accuracy_scores) / np.sum(accuracy_scores)
        
        # Calculate accuracy-weighted average
        weighted_sum = np.zeros_like(updates[0]["weights"])
        for i, update in enumerate(updates):
            weighted_sum += update["weights"] * normalized_scores[i]
        
        return weighted_sum

class FederatedLearningSystem:
    """Main federated learning coordinator"""
    
    def __init__(self):
        self.privacy_engine = PrivacyPreservationEngine()
        self.model_aggregator = FederatedModelAggregator()
        self.client_registry = {}
        self.active_training_rounds = {}
        self.completed_training_rounds = []
        self.global_models = {}
        self.reputation_scores = {}
        
    async def register_client(self, client_node: ClientNode) -> bool:
        """Register a new client in the federated learning network"""
        try:
            # Validate client credentials
            if not await self._validate_client_credentials(client_node):
                logger.warning(f"Client {client_node.id} failed credential validation")
                return False
            
            # Check if client already exists
            if client_node.id in self.client_registry:
                logger.warning(f"Client {client_node.id} already registered")
                return False
            
            # Register client
            self.client_registry[client_node.id] = client_node
            self.reputation_scores[client_node.id] = client_node.reputation_score
            
            logger.info(f"Successfully registered client {client_node.id} from {client_node.organization_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error registering client {client_node.id}: {e}")
            return False
    
    async def unregister_client(self, client_id: str) -> bool:
        """Unregister a client from the network"""
        try:
            if client_id not in self.client_registry:
                logger.warning(f"Client {client_id} not found in registry")
                return False
            
            # Remove from registry
            del self.client_registry[client_id]
            
            # Remove reputation score
            if client_id in self.reputation_scores:
                del self.reputation_scores[client_id]
            
            logger.info(f"Successfully unregistered client {client_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error unregistering client {client_id}: {e}")
            return False
    
    async def start_training_round(self, model_type: ModelType, 
                                 participating_clients: List[str] = None) -> str:
        """Start a new federated learning training round"""
        try:
            round_id = f"round_{len(self.completed_training_rounds) + 1}"
            round_number = len(self.completed_training_rounds) + 1
            
            # Select participating clients if not specified
            if participating_clients is None:
                participating_clients = await self._select_participating_clients(model_type)
            
            # Validate participating clients
            valid_clients = []
            for client_id in participating_clients:
                if client_id in self.client_registry:
                    valid_clients.append(client_id)
                else:
                    logger.warning(f"Client {client_id} not found in registry")
            
            if len(valid_clients) < 3:  # Minimum participants
                raise ValueError(f"Insufficient participating clients: {len(valid_clients)}")
            
            # Create training round
            training_round = TrainingRound(
                id=round_id,
                round_number=round_number,
                model_type=model_type,
                participating_clients=valid_clients,
                global_model_version=f"v{round_number}.0",
                start_time=datetime.utcnow()
            )
            
            self.active_training_rounds[round_id] = training_round
            
            # Notify participating clients
            await self._notify_clients_of_training_round(training_round)
            
            logger.info(f"Started training round {round_id} for {model_type.value} with {len(valid_clients)} clients")
            
            return round_id
            
        except Exception as e:
            logger.error(f"Error starting training round: {e}")
            raise
    
    async def submit_model_update(self, client_id: str, round_id: str, 
                                model_update: ModelUpdate) -> bool:
        """Submit a model update from a client"""
        try:
            # Validate client
            if client_id not in self.client_registry:
                logger.warning(f"Unknown client {client_id}")
                return False
            
            # Validate training round
            if round_id not in self.active_training_rounds:
                logger.warning(f"Unknown training round {round_id}")
                return False
            
            training_round = self.active_training_rounds[round_id]
            
            # Check if client is participating in this round
            if client_id not in training_round.participating_clients:
                logger.warning(f"Client {client_id} not participating in round {round_id}")
                return False
            
            # Store model update (in reality, this would be in a secure database)
            if not hasattr(training_round, 'model_updates'):
                training_round.model_updates = []
            
            training_round.model_updates.append(model_update)
            
            # Update client statistics
            client_node = self.client_registry[client_id]
            client_node.contributed_models += 1
            client_node.last_active = datetime.utcnow()
            
            # Check if we have enough updates to proceed with aggregation
            if len(training_round.model_updates) >= training_round.min_participants:
                await self._check_for_aggregation_opportunity(training_round)
            
            logger.info(f"Received model update from client {client_id} for round {round_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error submitting model update from {client_id}: {e}")
            return False
    
    async def complete_training_round(self, round_id: str) -> Dict[str, Any]:
        """Complete a training round and generate global model"""
        try:
            if round_id not in self.active_training_rounds:
                raise ValueError(f"Training round {round_id} not found")
            
            training_round = self.active_training_rounds[round_id]
            
            # Check if we have sufficient model updates
            if not hasattr(training_round, 'model_updates') or len(training_round.model_updates) == 0:
                raise ValueError("No model updates available for aggregation")
            
            # Aggregate models
            aggregation_result = self.model_aggregator.aggregate_models(training_round.model_updates)
            global_model = aggregation_result["global_model"]
            
            # Store global model
            model_key = f"{training_round.model_type.value}_global"
            self.global_models[model_key] = {
                "model_weights": global_model,
                "version": training_round.global_model_version,
                "round_id": round_id,
                "created_at": datetime.utcnow(),
                "participants": training_round.participating_clients,
                "statistics": aggregation_result["statistics"]
            }
            
            # Update training round
            training_round.end_time = datetime.utcnow()
            training_round.model_updates.clear()  # Clear updates to save memory
            
            # Move to completed rounds
            self.completed_training_rounds.append(training_round)
            del self.active_training_rounds[round_id]
            
            # Distribute global model to participating clients
            await self._distribute_global_model(training_round, global_model)
            
            logger.info(f"Completed training round {round_id} with global model {training_round.global_model_version}")
            
            return {
                "round_id": round_id,
                "global_model_version": training_round.global_model_version,
                "participants": len(training_round.participating_clients),
                "aggregation_statistics": aggregation_result["statistics"]
            }
            
        except Exception as e:
            logger.error(f"Error completing training round {round_id}: {e}")
            raise
    
    async def get_global_model(self, model_type: ModelType) -> Optional[Dict[str, Any]]:
        """Get the latest global model for a specific type"""
        model_key = f"{model_type.value}_global"
        return self.global_models.get(model_key)
    
    async def get_training_statistics(self) -> Dict[str, Any]:
        """Get comprehensive federated learning statistics"""
        total_clients = len(self.client_registry)
        active_rounds = len(self.active_training_rounds)
        completed_rounds = len(self.completed_training_rounds)
        
        # Calculate average round participation
        total_participants = sum(len(round.participating_clients) for round in self.completed_training_rounds)
        avg_participants = total_participants / completed_rounds if completed_rounds > 0 else 0
        
        # Model type distribution
        model_distribution = {}
        for round in self.completed_training_rounds:
            model_type = round.model_type.value
            model_distribution[model_type] = model_distribution.get(model_type, 0) + 1
        
        # Client activity statistics
        active_clients = sum(1 for client in self.client_registry.values() 
                           if (datetime.utcnow() - client.last_active).days < 7)
        
        return {
            "total_registered_clients": total_clients,
            "active_clients_7_days": active_clients,
            "active_training_rounds": active_rounds,
            "completed_training_rounds": completed_rounds,
            "average_participants_per_round": avg_participants,
            "model_type_distribution": model_distribution,
            "global_models_available": len(self.global_models),
            "total_network_contributions": sum(client.contributed_models for client in self.client_registry.values())
        }
    
    # Private helper methods
    
    async def _validate_client_credentials(self, client_node: ClientNode) -> bool:
        """Validate client credentials (simplified implementation)"""
        # In a real implementation, this would validate against a trusted certificate authority
        # For now, we'll do basic validation
        
        if not client_node.id or not client_node.organization_id:
            return False
        
        if not client_node.public_key:
            return False
        
        # Check if client ID follows expected format
        if not client_node.id.startswith("client_"):
            return False
        
        return True
    
    async def _select_participating_clients(self, model_type: ModelType) -> List[str]:
        """Select participating clients for a training round"""
        # Sort clients by reputation and activity
        eligible_clients = []
        
        for client_id, client_node in self.client_registry.items():
            # Check if client is eligible (active, good reputation, etc.)
            if (client_node.reputation_score > 0.5 and
                (datetime.utcnow() - client_node.last_active).days < 30):
                eligible_clients.append(client_id)
        
        # Select up to 10 clients (or fewer if not available)
        selected_clients = eligible_clients[:10]
        
        logger.info(f"Selected {len(selected_clients)} clients for {model_type.value} training")
        return selected_clients
    
    async def _notify_clients_of_training_round(self, training_round: TrainingRound):
        """Notify participating clients of a new training round"""
        # In a real implementation, this would send notifications to clients
        # For now, we'll just log it
        logger.info(f"Notifying clients {training_round.participating_clients} of training round {training_round.id}")
    
    async def _check_for_aggregation_opportunity(self, training_round: TrainingRound):
        """Check if we have enough updates to proceed with aggregation"""
        # Check if round has been running for minimum time
        elapsed_time = datetime.utcnow() - training_round.start_time
        
        if elapsed_time > timedelta(minutes=30) and len(training_round.model_updates) >= training_round.min_participants:
            # Automatically complete the round
            logger.info(f"Automatically completing round {training_round.id} due to time elapsed and sufficient participants")
            await self.complete_training_round(training_round.id)
    
    async def _distribute_global_model(self, training_round: TrainingRound, global_model: np.ndarray):
        """Distribute global model to participating clients"""
        # In a real implementation, this would securely distribute the model to clients
        # For now, we'll just log it
        logger.info(f"Distributing global model to {len(training_round.participating_clients)} clients")
    
    async def update_client_reputation(self, client_id: str, update_quality: float):
        """Update client reputation based on model update quality"""
        if client_id in self.reputation_scores:
            # Simple reputation update algorithm
            current_reputation = self.reputation_scores[client_id]
            new_reputation = (current_reputation * 0.9) + (update_quality * 0.1)
            self.reputation_scores[client_id] = max(0.0, min(1.0, new_reputation))

# Global federated learning system instance
federated_learning_system = FederatedLearningSystem()