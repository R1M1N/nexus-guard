"""
NEXUS GUARD - Configuration Management
Enterprise-grade configuration system for the cybersecurity platform
"""

import os
from typing import Dict, Any, Optional
from pydantic import BaseSettings, Field
from enum import Enum

class SecurityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    MAXIMUM = "MAXIMUM"

class DeploymentMode(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"

class NexusSettings(BaseSettings):
    """Core configuration settings for NEXUS GUARD platform"""
    
    # Application Settings
    APP_NAME: str = "NEXUS GUARD"
    VERSION: str = "2.0.0"
    DEBUG: bool = Field(default=False, env="DEBUG")
    DEPLOYMENT_MODE: DeploymentMode = Field(default=DeploymentMode.PRODUCTION, env="DEPLOYMENT_MODE")
    
    # Security Settings
    SECURITY_LEVEL: SecurityLevel = Field(default=SecurityLevel.HIGH, env="SECURITY_LEVEL")
    API_SECRET_KEY: str = Field(..., env="API_SECRET_KEY")
    JWT_SECRET_KEY: str = Field(..., env="JWT_SECRET_KEY")
    ENCRYPTION_KEY: str = Field(..., env="ENCRYPTION_KEY")
    
    # Database Configuration
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    REDIS_URL: str = Field(..., env="REDIS_URL")
    MONGODB_URL: str = Field(..., env="MONGODB_URL")
    
    # AI/ML Configuration
    AI_MODEL_PATH: str = Field(default="/app/models", env="AI_MODEL_PATH")
    FEDERATED_LEARNING_ENABLED: bool = Field(default=True, env="FEDERATED_LEARNING_ENABLED")
    PRIVACY_PRESERVATION_LEVEL: SecurityLevel = Field(default=SecurityLevel.HIGH, env="PRIVACY_PRESERVATION_LEVEL")
    
    # Threat Detection Thresholds
    ANOMALY_DETECTION_THRESHOLD: float = Field(default=0.85, env="ANOMALY_DETECTION_THRESHOLD")
    MALWARE_DETECTION_THRESHOLD: float = Field(default=0.90, env="MALWARE_DETECTION_THRESHOLD")
    INTRUSION_DETECTION_THRESHOLD: float = Field(default=0.95, env="INTRUSION_DETECTION_THRESHOLD")
    ZERO_DAY_DETECTION_THRESHOLD: float = Field(default=0.75, env="ZERO_DAY_DETECTION_THRESHOLD")
    
    # Response Configuration
    AUTOMATED_RESPONSE_ENABLED: bool = Field(default=True, env="AUTOMATED_RESPONSE_ENABLED")
    AUTO_ISOLATION_THRESHOLD: float = Field(default=0.95, env="AUTO_ISOLATION_THRESHOLD")
    HUMAN_VERIFICATION_REQUIRED: bool = Field(default=True, env="HUMAN_VERIFICATION_REQUIRED")
    
    # Network Monitoring
    NETWORK_MONITORING_ENABLED: bool = Field(default=True, env="NETWORK_MONITORING_ENABLED")
    WIRELESS_MONITORING_ENABLED: bool = Field(default=True, env="WIRELESS_MONITORING_ENABLED")
    PACKET_CAPTURE_ENABLED: bool = Field(default=True, env="PACKET_CAPTURE_ENABLED")
    
    # Blockchain Configuration
    BLOCKCHAIN_ENABLED: bool = Field(default=True, env="BLOCKCHAIN_ENABLED")
    BLOCKCHAIN_NETWORK: str = Field(default="hyperledger-fabric", env="BLOCKCHAIN_NETWORK")
    AUDIT_LOG_RETENTION_DAYS: int = Field(default=2555, env="AUDIT_LOG_RETENTION_DAYS")  # 7 years
    
    # Scalability Settings
    MAX_CONCURRENT_CONNECTIONS: int = Field(default=10000, env="MAX_CONCURRENT_CONNECTIONS")
    WORKER_PROCESSES: int = Field(default=4, env="WORKER_PROCESSES")
    MODEL_CACHE_SIZE_GB: int = Field(default=100, env="MODEL_CACHE_SIZE_GB")
    
    # Compliance Settings
    GDPR_COMPLIANCE: bool = Field(default=True, env="GDPR_COMPLIANCE")
    HIPAA_COMPLIANCE: bool = Field(default=False, env="HIPAA_COMPLIANCE")
    SOX_COMPLIANCE: bool = Field(default=False, env="SOX_COMPLIANCE")
    ISO27001_COMPLIANCE: bool = Field(default=True, env="ISO27001_COMPLIANCE")
    
    # Monitoring & Observability
    PROMETHEUS_ENABLED: bool = Field(default=True, env="PROMETHEUS_ENABLED")
    JAEGER_ENABLED: bool = Field(default=True, env="JAEGER_ENABLED")
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    
    # External Integrations
    SIEM_INTEGRATION_ENABLED: bool = Field(default=True, env="SIEM_INTEGRATION_ENABLED")
    THREAT_INTEL_API_KEY: Optional[str] = Field(default=None, env="THREAT_INTEL_API_KEY")
    VIRUS_TOTAL_API_KEY: Optional[str] = Field(default=None, env="VIRUS_TOTAL_API_KEY")
    
    class Config:
        env_file = ".env"
        case_sensitive = True
    
    def get_threat_detection_config(self) -> Dict[str, Any]:
        """Return threat detection configuration"""
        return {
            "anomaly_threshold": self.ANOMALY_DETECTION_THRESHOLD,
            "malware_threshold": self.MALWARE_DETECTION_THRESHOLD,
            "intrusion_threshold": self.INTRUSION_DETECTION_THRESHOLD,
            "zero_day_threshold": self.ZERO_DAY_DETECTION_THRESHOLD,
            "automated_response": self.AUTOMATED_RESPONSE_ENABLED,
            "auto_isolation_threshold": self.AUTO_ISOLATION_THRESHOLD
        }
    
    def get_compliance_requirements(self) -> Dict[str, bool]:
        """Return compliance requirements"""
        return {
            "gdpr": self.GDPR_COMPLIANCE,
            "hipaa": self.HIPAA_COMPLIANCE,
            "sox": self.SOX_COMPLIANCE,
            "iso27001": self.ISO27001_COMPLIANCE
        }
    
    def is_production_ready(self) -> bool:
        """Check if configuration is production ready"""
        return (
            self.DEPLOYMENT_MODE == DeploymentMode.PRODUCTION and
            self.API_SECRET_KEY != "change-me" and
            self.JWT_SECRET_KEY != "change-me" and
            self.ENCRYPTION_KEY != "change-me" and
            self.DATABASE_URL != "sqlite:///./nexus.db"
        )

# Global settings instance
settings = NexusSettings()

# Security configuration constants
class SecurityConstants:
    """Security-related constants and configurations"""
    
    # Encryption Algorithms
    ENCRYPTION_ALGORITHM = "AES-256-GCM"
    HASH_ALGORITHM = "SHA-256"
    KEY_DERIVATION = "PBKDF2"
    
    # JWT Configuration
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION_HOURS = 24
    REFRESH_TOKEN_EXPIRATION_DAYS = 30
    
    # Rate Limiting
    API_RATE_LIMIT_PER_MINUTE = 1000
    LOGIN_ATTEMPTS_LIMIT = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES = 30
    
    # Threat Categories
    THREAT_CATEGORIES = [
        "MALWARE",
        "PHISHING", 
        "RANSOMWARE",
        "APT",
        "DDoS",
        "DATA_BREACH",
        "INSIDER_THREAT",
        "SUPPLY_CHAIN",
        "ZERO_DAY",
        "ADVANCED_SOCIAL_ENGINEERING"
    ]
    
    # Risk Levels
    RISK_LEVELS = {
        "CRITICAL": {"value": 5, "color": "#FF0000", "response_time": "immediate"},
        "HIGH": {"value": 4, "color": "#FF4500", "response_time": "< 5 minutes"},
        "MEDIUM": {"value": 3, "color": "#FFA500", "response_time": "< 30 minutes"},
        "LOW": {"value": 2, "color": "#FFD700", "response_time": "< 2 hours"},
        "INFO": {"value": 1, "color": "#00FF00", "response_time": "monitor"}
    }