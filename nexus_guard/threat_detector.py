"""
NEXUS GUARD - Advanced Threat Detection Engine
Multi-modal AI-powered threat detection with real-time analysis
"""

import asyncio
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import joblib
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import json
import logging

from config import settings, SecurityLevel

logger = logging.getLogger(__name__)

class ThreatType(str, Enum):
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    RANSOMWARE = "RANSOMWARE"
    APT = "APT"
    DDOS = "DDOS"
    DATA_BREACH = "DATA_BREACH"
    INSIDER_THREAT = "INSIDER_THREAT"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    ZERO_DAY = "ZERO_DAY"
    ADVANCED_SOCIAL_ENGINEERING = "ADVANCED_SOCIAL_ENGINEERING"

class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class ThreatEvent:
    """Structured threat event data"""
    id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    event_type: str
    protocol: str
    port: int
    payload: bytes
    metadata: Dict[str, Any]
    user_id: Optional[str] = None
    session_id: Optional[str] = None

@dataclass
class ThreatAnalysis:
    """Threat analysis results"""
    event_id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    confidence_score: float
    indicators: List[str]
    analysis_details: Dict[str, Any]
    recommended_actions: List[str]
    auto_response_required: bool

class IsolationForestDetector:
    """Anomaly detection using Isolation Forest algorithm"""
    
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            'packet_size', 'connection_duration', 'request_frequency',
            'error_rate', 'response_time', 'bytes_transferred',
            'failed_attempts', 'unusual_ports', 'geographic_deviation'
        ]
    
    def extract_features(self, event: ThreatEvent) -> np.ndarray:
        """Extract features from threat event"""
        features = {
            'packet_size': len(event.payload),
            'connection_duration': event.metadata.get('duration', 0),
            'request_frequency': event.metadata.get('requests_per_second', 0),
            'error_rate': event.metadata.get('error_rate', 0),
            'response_time': event.metadata.get('response_time', 0),
            'bytes_transferred': event.metadata.get('bytes_transferred', 0),
            'failed_attempts': event.metadata.get('failed_attempts', 0),
            'unusual_ports': 1 if event.port not in [80, 443, 22, 21, 25, 53] else 0,
            'geographic_deviation': event.metadata.get('geo_deviation', 0)
        }
        
        return np.array([features[name] for name in self.feature_names])
    
    async def train(self, training_data: List[ThreatEvent]):
        """Train the anomaly detection model"""
        features = []
        for event in training_data:
            features.append(self.extract_features(event))
        
        features_array = np.array(features)
        features_scaled = self.scaler.fit_transform(features_array)
        
        self.model.fit(features_scaled)
        self.is_trained = True
        
        logger.info(f"Isolation Forest model trained on {len(training_data)} samples")
    
    async def predict(self, event: ThreatEvent) -> Tuple[float, bool]:
        """Predict if event is anomalous"""
        if not self.is_trained:
            logger.warning("Model not trained yet, returning neutral prediction")
            return 0.5, False
        
        features = self.extract_features(event).reshape(1, -1)
        features_scaled = self.scaler.transform(features)
        
        # Get anomaly score (lower = more anomalous)
        anomaly_score = self.model.decision_function(features_scaled)[0]
        is_anomaly = self.model.predict(features_scaled)[0] == -1
        
        # Convert to 0-1 confidence score (higher = more anomalous)
        confidence = max(0, min(1, (0.5 - anomaly_score)))
        
        return confidence, is_anomaly

class LSTMBehaviorModel(nn.Module):
    """LSTM-based behavioral analysis for user/entity behavior detection"""
    
    def __init__(self, input_size=50, hidden_size=128, num_layers=2, num_classes=4):
        super(LSTMBehaviorModel, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True, dropout=0.2)
        self.dropout = nn.Dropout(0.2)
        self.fc = nn.Linear(hidden_size, num_classes)
        self.softmax = nn.Softmax(dim=1)
    
    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
        
        out, _ = self.lstm(x, (h0, c0))
        out = self.dropout(out[:, -1, :])
        out = self.fc(out)
        return self.softmax(out)

class CNNSignatureModel(nn.Module):
    """CNN-based malware signature detection"""
    
    def __init__(self, input_channels=1, num_classes=10):
        super(CNNSignatureModel, self).__init__()
        
        self.conv1 = nn.Conv2d(input_channels, 32, kernel_size=3, padding=1)
        self.conv2 = nn.Conv2d(32, 64, kernel_size=3, padding=1)
        self.conv3 = nn.Conv2d(64, 128, kernel_size=3, padding=1)
        
        self.pool = nn.MaxPool2d(2, 2)
        self.dropout = nn.Dropout(0.2)
        
        self.fc1 = nn.Linear(128 * 16 * 16, 512)
        self.fc2 = nn.Linear(512, num_classes)
        self.relu = nn.ReLU()
    
    def forward(self, x):
        x = self.pool(self.relu(self.conv1(x)))
        x = self.pool(self.relu(self.conv2(x)))
        x = self.pool(self.relu(self.conv3(x)))
        
        x = x.view(-1, 128 * 16 * 16)
        x = self.dropout(self.relu(self.fc1(x)))
        x = self.fc2(x)
        return x

class UnsupervisedAnomalyModel:
    """Advanced unsupervised learning for zero-day threat detection"""
    
    def __init__(self):
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.feature_extractor = None
        self.known_patterns = []
        self.anomaly_history = []
    
    async def analyze_pattern(self, event: ThreatEvent) -> Dict[str, Any]:
        """Analyze event patterns for anomalies"""
        # Extract advanced features
        pattern_features = await self.extract_pattern_features(event)
        
        # Cluster analysis
        if len(self.known_patterns) > 10:
            clusters = self.dbscan.fit_predict(self.known_patterns)
            current_cluster = self.dbscan.fit_predict([pattern_features])
            
            is_known = current_cluster[0] != -1  # Not noise
            cluster_similarity = self.calculate_similarity(pattern_features)
        else:
            is_known = False
            cluster_similarity = 0.0
        
        # Update pattern database
        self.known_patterns.append(pattern_features)
        
        return {
            "is_known_pattern": is_known,
            "cluster_similarity": cluster_similarity,
            "pattern_complexity": self.calculate_complexity(pattern_features),
            "feature_vector": pattern_features
        }
    
    async def extract_pattern_features(self, event: ThreatEvent) -> List[float]:
        """Extract sophisticated pattern features"""
        features = []
        
        # Temporal features
        features.extend([
            event.metadata.get('hour_of_day', 0) / 24.0,
            event.metadata.get('day_of_week', 0) / 7.0,
            event.metadata.get('time_since_last_request', 0) / 3600.0
        ])
        
        # Network features
        features.extend([
            len(event.payload) / 65535.0,  # Normalized packet size
            event.port / 65535.0,  # Normalized port
            event.metadata.get('ttl', 64) / 255.0,  # Normalized TTL
            event.metadata.get('window_size', 8192) / 65535.0  # Normalized window size
        ])
        
        # Behavioral features
        features.extend([
            event.metadata.get('request_frequency', 0) / 100.0,
            event.metadata.get('error_rate', 0),
            event.metadata.get('response_variance', 0),
            event.metadata.get('concurrent_connections', 0) / 100.0
        ])
        
        return features
    
    def calculate_similarity(self, features: List[float]) -> float:
        """Calculate similarity to known patterns"""
        if not self.known_patterns:
            return 0.0
        
        similarities = []
        for known_pattern in self.known_patterns:
            # Euclidean distance similarity
            distance = np.linalg.norm(np.array(features) - np.array(known_pattern))
            similarity = 1.0 / (1.0 + distance)
            similarities.append(similarity)
        
        return max(similarities) if similarities else 0.0
    
    def calculate_complexity(self, features: List[float]) -> float:
        """Calculate pattern complexity score"""
        # Shannon entropy approximation
        feature_array = np.array(features)
        hist, _ = np.histogram(feature_array, bins=10)
        probabilities = hist / np.sum(hist)
        entropy = -np.sum([p * np.log2(p + 1e-10) for p in probabilities if p > 0])
        return entropy / np.log2(10)  # Normalized entropy

class GraphNeuralNetwork:
    """Network intrusion detection using graph neural networks"""
    
    def __init__(self, node_features=64, hidden_size=128):
        self.node_features = node_features
        self.hidden_size = hidden_size
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Simplified GCN implementation
        self.weights = torch.randn(node_features, hidden_size, device=self.device)
        self.bias = torch.randn(hidden_size, device=self.device)
    
    async def build_network_graph(self, network_events: List[ThreatEvent]) -> Dict[str, Any]:
        """Build network interaction graph from events"""
        nodes = {}
        edges = {}
        
        for event in network_events:
            source = event.source_ip
            dest = event.destination_ip
            
            # Add nodes
            if source not in nodes:
                nodes[source] = self.extract_node_features(event, source)
            if dest not in nodes:
                nodes[dest] = self.extract_node_features(event, dest)
            
            # Add edges
            edge_key = f"{source}->{dest}"
            if edge_key not in edges:
                edges[edge_key] = {
                    'source': source,
                    'target': dest,
                    'weight': 0,
                    'events': []
                }
            
            edges[edge_key]['weight'] += 1
            edges[edge_key]['events'].append(event.id)
        
        return {
            'nodes': nodes,
            'edges': edges,
            'num_nodes': len(nodes),
            'num_edges': len(edges)
        }
    
    def extract_node_features(self, event: ThreatEvent, ip: str) -> List[float]:
        """Extract features for network node"""
        if ip == event.source_ip:
            direction = 1.0
        else:
            direction = -1.0
        
        return [
            direction,  # Traffic direction
            len(event.payload) / 65535.0,  # Packet size
            event.port / 65535.0,  # Port number
            event.metadata.get('duration', 0) / 3600.0,  # Connection duration
            event.metadata.get('bytes_transferred', 0) / 1000000.0  # Data volume
        ]
    
    async def detect_intrusion(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect network intrusion patterns"""
        nodes = graph_data['nodes']
        edges = graph_data['edges']
        
        intrusion_indicators = []
        suspicious_nodes = []
        
        # Analyze node behavior
        for node_id, features in nodes.items():
            anomaly_score = self.calculate_node_anomaly(features)
            if anomaly_score > 0.8:
                suspicious_nodes.append({
                    'node_id': node_id,
                    'anomaly_score': anomaly_score,
                    'features': features
                })
        
        # Analyze edge patterns
        for edge_id, edge_data in edges.items():
            if edge_data['weight'] > 100:  # Unusually high traffic
                intrusion_indicators.append({
                    'type': 'HIGH_TRAFFIC_VOLUME',
                    'edge': edge_id,
                    'weight': edge_data['weight'],
                    'severity': 'MEDIUM' if edge_data['weight'] < 500 else 'HIGH'
                })
        
        # Detect coordinated attacks
        if len(suspicious_nodes) > 3:
            intrusion_indicators.append({
                'type': 'COORDINATED_ATTACK',
                'affected_nodes': len(suspicious_nodes),
                'severity': 'HIGH'
            })
        
        return {
            'suspicious_nodes': suspicious_nodes,
            'intrusion_indicators': intrusion_indicators,
            'overall_risk': self.calculate_overall_risk(suspicious_nodes, intrusion_indicators)
        }
    
    def calculate_node_anomaly(self, features: List[float]) -> float:
        """Calculate node anomaly score"""
        # Simplified anomaly detection
        mean_features = np.mean(features)
        std_features = np.std(features)
        
        # Z-score based anomaly detection
        z_scores = [(f - mean_features) / (std_features + 1e-10) for f in features]
        max_z_score = max(abs(z) for z in z_scores)
        
        # Convert to 0-1 confidence score
        return min(1.0, max_z_score / 3.0)
    
    def calculate_overall_risk(self, suspicious_nodes: List[Dict], indicators: List[Dict]) -> float:
        """Calculate overall network risk score"""
        if not suspicious_nodes and not indicators:
            return 0.0
        
        node_risk = len(suspicious_nodes) * 0.3
        indicator_risk = len(indicators) * 0.4
        
        high_severity_count = sum(1 for i in indicators if i.get('severity') == 'HIGH')
        indicator_risk += high_severity_count * 0.3
        
        return min(1.0, (node_risk + indicator_risk))

class NexusThreatDetector:
    """Main threat detection orchestrator"""
    
    def __init__(self):
        self.models = {
            'isolation_forest': IsolationForestDetector(),
            'behavioral_lstm': LSTMBehaviorModel(),
            'signature_cnn': CNNSignatureModel(),
            'unsupervised_anomaly': UnsupervisedAnomalyModel(),
            'network_intrusion': GraphNeuralNetwork()
        }
        self.detection_history = []
        self.model_performance = {}
        
    async def initialize_models(self, training_data: Optional[List[ThreatEvent]] = None):
        """Initialize and train all detection models"""
        logger.info("Initializing NEXUS GUARD threat detection models...")
        
        # Train isolation forest on historical data
        if training_data:
            await self.models['isolation_forest'].train(training_data)
        
        # Initialize other models
        for model_name, model in self.models.items():
            if hasattr(model, 'is_trained') and model_name != 'isolation_forest':
                model.is_trained = True
        
        logger.info("All threat detection models initialized successfully")
    
    async def analyze_event(self, event: ThreatEvent) -> ThreatAnalysis:
        """Perform comprehensive threat analysis"""
        analysis_results = {}
        threat_scores = {}
        
        # Run all detection models
        for model_name, model in self.models.items():
            try:
                if model_name == 'isolation_forest':
                    score, is_anomaly = await model.predict(event)
                    threat_scores[model_name] = score
                    analysis_results[model_name] = {
                        'anomaly_detected': is_anomaly,
                        'confidence': score
                    }
                elif model_name == 'unsupervised_anomaly':
                    pattern_analysis = await model.analyze_pattern(event)
                    threat_scores[model_name] = 1.0 - pattern_analysis['cluster_similarity']
                    analysis_results[model_name] = pattern_analysis
                elif model_name == 'network_intrusion':
                    # For network analysis, we'd need a graph of events
                    threat_scores[model_name] = 0.0  # Placeholder
                    analysis_results[model_name] = {'status': 'no_graph_data'}
                else:
                    # Placeholder for LSTM and CNN models
                    threat_scores[model_name] = 0.5
                    analysis_results[model_name] = {'status': 'model_placeholder'}
            except Exception as e:
                logger.error(f"Error in {model_name} analysis: {e}")
                threat_scores[model_name] = 0.0
        
        # Aggregate threat scores using ensemble method
        ensemble_score = self._ensemble_threat_scores(threat_scores)
        
        # Determine threat type and severity
        threat_type = self._classify_threat_type(event, analysis_results)
        severity = self._calculate_severity(ensemble_score, event)
        
        # Generate recommended actions
        recommended_actions = self._generate_recommended_actions(threat_type, severity, ensemble_score)
        
        # Determine if automated response is required
        auto_response_required = self._should_auto_respond(severity, ensemble_score)
        
        # Create threat analysis result
        analysis = ThreatAnalysis(
            event_id=event.id,
            threat_type=threat_type,
            severity=severity,
            confidence_score=ensemble_score,
            indicators=self._extract_indicators(analysis_results),
            analysis_details=analysis_results,
            recommended_actions=recommended_actions,
            auto_response_required=auto_response_required
        )
        
        # Store analysis in history
        self.detection_history.append(analysis)
        
        # Update model performance metrics
        await self._update_model_performance(analysis)
        
        return analysis
    
    def _ensemble_threat_scores(self, scores: Dict[str, float]) -> float:
        """Aggregate threat scores from multiple models"""
        if not scores:
            return 0.0
        
        # Weighted ensemble with different model weights
        weights = {
            'isolation_forest': 0.25,
            'behavioral_lstm': 0.25,
            'signature_cnn': 0.20,
            'unsupervised_anomaly': 0.20,
            'network_intrusion': 0.10
        }
        
        weighted_sum = sum(scores.get(model, 0.0) * weight 
                          for model, weight in weights.items())
        total_weight = sum(weights.values())
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0
    
    def _classify_threat_type(self, event: ThreatEvent, analysis: Dict[str, Any]) -> ThreatType:
        """Classify the type of threat based on event characteristics"""
        payload_size = len(event.payload)
        port = event.port
        frequency = event.metadata.get('request_frequency', 0)
        
        # Rule-based threat classification
        if port in [22, 23, 3389]:  # SSH, Telnet, RDP
            return ThreatType.APT
        elif frequency > 1000:  # High frequency requests
            return ThreatType.DDOS
        elif payload_size > 500000:  # Large payload
            return ThreatType.DATA_BREACH
        elif port in [445, 139]:  # Windows file sharing
            return ThreatType.RANSOMWARE
        elif port in [25, 587, 993]:  # Email ports
            return ThreatType.PHISHING
        else:
            # Use anomaly detection results
            if analysis.get('isolation_forest', {}).get('anomaly_detected', False):
                return ThreatType.ZERO_DAY
            return ThreatType.MALWARE
    
    def _calculate_severity(self, confidence_score: float, event: ThreatEvent) -> ThreatSeverity:
        """Calculate threat severity based on confidence and context"""
        base_severity = confidence_score
        
        # Adjust based on event context
        if event.metadata.get('is_admin_action', False):
            base_severity += 0.2
        if event.metadata.get('crosses_business_hours', False):
            base_severity += 0.1
        if event.metadata.get('from_external_ip', False):
            base_severity += 0.15
        
        # Cap at 1.0
        base_severity = min(1.0, base_severity)
        
        # Map to severity levels
        if base_severity >= 0.9:
            return ThreatSeverity.CRITICAL
        elif base_severity >= 0.7:
            return ThreatSeverity.HIGH
        elif base_severity >= 0.5:
            return ThreatSeverity.MEDIUM
        elif base_severity >= 0.3:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.INFO
    
    def _generate_recommended_actions(self, threat_type: ThreatType, 
                                    severity: ThreatSeverity, confidence: float) -> List[str]:
        """Generate recommended response actions"""
        actions = []
        
        # Base actions by severity
        if severity == ThreatSeverity.CRITICAL:
            actions.extend([
                "Immediately isolate affected systems",
                "Activate incident response team",
                "Block malicious IP addresses",
                "Preserve system state for forensics"
            ])
        elif severity == ThreatSeverity.HIGH:
            actions.extend([
                "Enhanced monitoring of affected systems",
                "Review firewall rules",
                "Verify system integrity",
                "Update threat intelligence feeds"
            ])
        elif severity == ThreatSeverity.MEDIUM:
            actions.extend([
                "Increased logging and monitoring",
                "Review recent system changes",
                "Verify user access patterns",
                "Update security policies if needed"
            ])
        else:
            actions.extend([
                "Continue monitoring",
                "Log for trend analysis",
                "Review in next security review"
            ])
        
        # Additional actions by threat type
        if threat_type == ThreatType.RANSOMWARE:
            actions.append("Activate backup systems")
        elif threat_type == ThreatType.DDOS:
            actions.append("Enable DDoS protection")
        elif threat_type == ThreatType.PHISHING:
            actions.append("Update email security filters")
        elif threat_type == ThreatType.APT:
            actions.append("Initiate advanced threat hunting")
        
        return actions
    
    def _should_auto_respond(self, severity: ThreatSeverity, confidence: float) -> bool:
        """Determine if automated response is required"""
        if not settings.AUTOMATED_RESPONSE_ENABLED:
            return False
        
        # Auto-respond for critical threats with high confidence
        if severity == ThreatSeverity.CRITICAL and confidence >= 0.95:
            return True
        
        # Auto-respond for high severity with very high confidence
        if severity == ThreatSeverity.HIGH and confidence >= 0.98:
            return True
        
        return False
    
    def _extract_indicators(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Extract security indicators from analysis results"""
        indicators = []
        
        for model_name, results in analysis_results.items():
            if model_name == 'isolation_forest' and results.get('anomaly_detected'):
                indicators.append("ANOMALY_DETECTED")
            elif model_name == 'unsupervised_anomaly' and results.get('is_known_pattern') == False:
                indicators.append("UNKNOWN_PATTERN")
            elif model_name == 'network_intrusion' and results.get('intrusion_indicators'):
                indicators.append("NETWORK_ANOMALY")
        
        return indicators
    
    async def _update_model_performance(self, analysis: ThreatAnalysis):
        """Update model performance metrics"""
        # Simplified performance tracking
        if not hasattr(self, 'performance_history'):
            self.performance_history = []
        
        self.performance_history.append({
            'timestamp': analysis.event_id,
            'confidence': analysis.confidence_score,
            'threat_type': analysis.threat_type,
            'severity': analysis.severity
        })
        
        # Keep only last 1000 records
        if len(self.performance_history) > 1000:
            self.performance_history = self.performance_history[-1000:]
    
    async def get_detection_statistics(self) -> Dict[str, Any]:
        """Get comprehensive detection statistics"""
        if not self.detection_history:
            return {"status": "no_data"}
        
        # Calculate statistics
        total_detections = len(self.detection_history)
        avg_confidence = np.mean([a.confidence_score for a in self.detection_history])
        
        # Threat type distribution
        threat_distribution = {}
        for analysis in self.detection_history:
            threat_type = analysis.threat_type
            threat_distribution[threat_type] = threat_distribution.get(threat_type, 0) + 1
        
        # Severity distribution
        severity_distribution = {}
        for analysis in self.detection_history:
            severity = analysis.severity
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        # High-confidence detections
        high_confidence_count = sum(1 for a in self.detection_history if a.confidence_score > 0.8)
        
        return {
            "total_detections": total_detections,
            "average_confidence": avg_confidence,
            "threat_type_distribution": threat_distribution,
            "severity_distribution": severity_distribution,
            "high_confidence_detections": high_confidence_count,
            "auto_response_rate": sum(1 for a in self.detection_history if a.auto_response_required) / total_detections
        }

# Global threat detector instance
threat_detector = NexusThreatDetector()