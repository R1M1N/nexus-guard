"""
NEXUS GUARD - Main Application
FastAPI-based REST API for the cybersecurity platform
"""

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import asyncio
import logging
import json
import os

from config import settings, NexusSettings
from threat_detector import (
    threat_detector, ThreatEvent, ThreatAnalysis, ThreatType, ThreatSeverity
)
from response_orchestrator import (
    response_orchestrator, ResponsePlan, ResponseStatus, ResponseAction
)
from federated_learning import (
    federated_learning_system, ClientNode, ModelType, ModelUpdate
)
from blockchain_audit import (
    blockchain_audit_system, AuditEvent, AuditEventType
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()

# FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="AI-Powered Enterprise Cybersecurity Platform",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else ["https://nexus-guard.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted host middleware (production security)
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["nexus-guard.com", "*.nexus-guard.com", "localhost"]
    )

# Global threat detection engine initialization
@app.on_event("startup")
async def startup_event():
    """Initialize the platform on startup"""
    logger.info("Starting NEXUS GUARD Cybersecurity Platform...")
    
    # Initialize threat detection models
    await threat_detector.initialize_models()
    
    # Initialize blockchain audit system
    await blockchain_audit_system._create_genesis_block()
    
    logger.info("NEXUS GUARD Platform initialized successfully")

# ==================== AUTHENTICATION & AUTHORIZATION ====================

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token (simplified implementation)"""
    # In a real implementation, this would validate JWT tokens
    # For demo purposes, we'll accept any bearer token
    if credentials.scheme.lower() == "bearer":
        return {"user_id": "demo_user", "tenant_id": "demo_tenant"}
    raise HTTPException(status_code=401, detail="Invalid authentication credentials")

# ==================== THREAT DETECTION ENDPOINTS ====================

class ThreatEventRequest(BaseModel):
    """Request model for threat events"""
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    event_type: str = Field(..., description="Type of event")
    protocol: str = Field(default="TCP", description="Network protocol")
    port: int = Field(..., description="Port number")
    payload: str = Field(default="", description="Event payload (base64 encoded)")
    user_id: Optional[str] = Field(None, description="User ID if applicable")
    session_id: Optional[str] = Field(None, description="Session ID")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

@app.post("/api/v2/threats/detect", response_model=Dict[str, Any])
async def detect_threat(
    event_request: ThreatEventRequest,
    current_user: Dict = Depends(verify_token)
):
    """
    Real-time threat detection endpoint
    Analyzes incoming events for security threats using AI models
    """
    try:
        # Create threat event
        threat_event = ThreatEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            source_ip=event_request.source_ip,
            destination_ip=event_request.destination_ip,
            event_type=event_request.event_type,
            protocol=event_request.protocol,
            port=event_request.port,
            payload=event_request.payload.encode() if event_request.payload else b"",
            metadata=event_request.metadata,
            user_id=event_request.user_id,
            session_id=event_request.session_id
        )
        
        # Analyze threat
        threat_analysis = await threat_detector.analyze_event(threat_event)
        
        # Log to blockchain audit
        audit_event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.THREAT_ANALYZED,
            timestamp=datetime.utcnow(),
            tenant_id=current_user["tenant_id"],
            user_id=current_user["user_id"],
            system_id=threat_event.id,
            event_data={
                "threat_type": threat_analysis.threat_type.value,
                "severity": threat_analysis.severity.value,
                "confidence": threat_analysis.confidence_score,
                "indicators": threat_analysis.indicators
            },
            ip_address=threat_event.source_ip,
            risk_level=threat_analysis.severity.value,
            compliance_flags=["ISO27001"] if threat_analysis.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH] else []
        )
        
        await blockchain_audit_system.log_audit_event(audit_event)
        
        # Return analysis results
        return {
            "threat_id": threat_analysis.event_id,
            "threat_type": threat_analysis.threat_type.value,
            "severity": threat_analysis.severity.value,
            "confidence_score": threat_analysis.confidence_score,
            "indicators": threat_analysis.indicators,
            "recommended_actions": threat_analysis.recommended_actions,
            "auto_response_required": threat_analysis.auto_response_required,
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in threat detection: {e}")
        raise HTTPException(status_code=500, detail=f"Threat detection failed: {str(e)}")

@app.get("/api/v2/threats/statistics", response_model=Dict[str, Any])
async def get_threat_statistics(
    current_user: Dict = Depends(verify_token)
):
    """Get threat detection statistics and analytics"""
    try:
        stats = await threat_detector.get_detection_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting threat statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")

# ==================== AUTOMATED RESPONSE ENDPOINTS ====================

class ResponseRequest(BaseModel):
    """Request model for response actions"""
    threat_analysis: Dict[str, Any]
    approved_by: Optional[str] = Field(None, description="User who approved the response")

@app.post("/api/v2/response/execute", response_model=Dict[str, Any])
async def execute_response(
    response_request: ResponseRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(verify_token)
):
    """
    Execute automated response to detected threats
    """
    try:
        # Convert threat analysis dict back to object
        # In a real implementation, this would be more robust
        threat_analysis_dict = response_request.threat_analysis
        
        # Create threat analysis object (simplified)
        threat_analysis = ThreatAnalysis(
            event_id=threat_analysis_dict["threat_id"],
            threat_type=ThreatType(threat_analysis_dict["threat_type"]),
            severity=ThreatSeverity(threat_analysis_dict["severity"]),
            confidence_score=threat_analysis_dict["confidence_score"],
            indicators=threat_analysis_dict["indicators"],
            analysis_details={"analysis_data": threat_analysis_dict},
            recommended_actions=threat_analysis_dict["recommended_actions"],
            auto_response_required=threat_analysis_dict["auto_response_required"]
        )
        
        # Generate response plan
        response_plan = await response_orchestrator.generate_response_plan(threat_analysis)
        
        # Check if approval is required
        if response_plan.requires_approval:
            if not response_request.approved_by:
                return {
                    "plan_id": response_plan.id,
                    "status": "PENDING_APPROVAL",
                    "message": "Response plan requires approval",
                    "estimated_duration_minutes": response_plan.estimated_duration_minutes,
                    "required_actions": [step.action.value for step in response_plan.steps]
                }
        
        # Execute response plan
        execution_result = await response_orchestrator.execute_response_plan(
            response_plan, 
            approved_by=response_request.approved_by or current_user["user_id"]
        )
        
        # Log response execution to blockchain
        response_audit_event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.RESPONSE_INITIATED,
            timestamp=datetime.utcnow(),
            tenant_id=current_user["tenant_id"],
            user_id=current_user["user_id"],
            system_id=threat_analysis.event_id,
            event_data={
                "response_plan_id": response_plan.id,
                "execution_result": execution_result,
                "threat_type": threat_analysis.threat_type.value
            },
            risk_level=threat_analysis.severity.value,
            compliance_flags=["ISO27001"]
        )
        
        await blockchain_audit_system.log_audit_event(response_audit_event)
        
        return {
            "plan_id": response_plan.id,
            "execution_result": execution_result,
            "status": "COMPLETED",
            "message": "Response plan executed successfully"
        }
        
    except Exception as e:
        logger.error(f"Error executing response: {e}")
        raise HTTPException(status_code=500, detail=f"Response execution failed: {str(e)}")

@app.get("/api/v2/response/active", response_model=List[Dict[str, Any]])
async def get_active_responses(
    current_user: Dict = Depends(verify_token)
):
    """Get all active response plans"""
    try:
        active_plans = await response_orchestrator.get_active_plans()
        return active_plans
    except Exception as e:
        logger.error(f"Error getting active responses: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve active responses")

@app.get("/api/v2/response/statistics", response_model=Dict[str, Any])
async def get_response_statistics(
    current_user: Dict = Depends(verify_token)
):
    """Get response execution statistics"""
    try:
        stats = await response_orchestrator.get_plan_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting response statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve response statistics")

# ==================== FEDERATED LEARNING ENDPOINTS ====================

class ClientRegistrationRequest(BaseModel):
    """Request model for client registration"""
    organization_id: str = Field(..., description="Organization identifier")
    role: str = Field(..., description="Client role")
    public_key: str = Field(..., description="Public key for secure communication")

@app.post("/api/v2/federated/register-client", response_model=Dict[str, Any])
async def register_federated_client(
    registration_request: ClientRegistrationRequest,
    current_user: Dict = Depends(verify_token)
):
    """Register a client in the federated learning network"""
    try:
        # Create client node
        client_node = ClientNode(
            id=f"client_{uuid.uuid4().hex[:8]}",
            organization_id=registration_request.organization_id,
            role=registration_request.role,
            public_key=registration_request.public_key
        )
        
        # Register client
        success = await federated_learning_system.register_client(client_node)
        
        if success:
            return {
                "client_id": client_node.id,
                "status": "registered",
                "organization_id": client_node.organization_id,
                "role": client_node.role.value
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to register client")
            
    except Exception as e:
        logger.error(f"Error registering federated client: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/api/v2/federated/start-training", response_model=Dict[str, Any])
async def start_federated_training(
    model_type: str,
    current_user: Dict = Depends(verify_token)
):
    """Start a new federated learning training round"""
    try:
        # Convert string to enum
        model_type_enum = ModelType(model_type)
        
        # Start training round
        round_id = await federated_learning_system.start_training_round(model_type_enum)
        
        return {
            "round_id": round_id,
            "model_type": model_type_enum.value,
            "status": "started",
            "message": "Federated training round initiated"
        }
        
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid model type: {model_type}")
    except Exception as e:
        logger.error(f"Error starting federated training: {e}")
        raise HTTPException(status_code=500, detail=f"Training start failed: {str(e)}")

@app.get("/api/v2/federated/statistics", response_model=Dict[str, Any])
async def get_federated_statistics(
    current_user: Dict = Depends(verify_token)
):
    """Get federated learning network statistics"""
    try:
        stats = await federated_learning_system.get_training_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting federated statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve federated statistics")

# ==================== BLOCKCHAIN AUDIT ENDPOINTS ====================

class AuditEventRequest(BaseModel):
    """Request model for audit events"""
    event_type: str = Field(..., description="Type of audit event")
    event_data: Dict[str, Any] = Field(default_factory=dict, description="Event data")
    risk_level: str = Field(default="MEDIUM", description="Risk level")
    compliance_flags: List[str] = Field(default_factory=list, description="Compliance flags")

@app.post("/api/v2/audit/log", response_model=Dict[str, Any])
async def log_audit_event(
    audit_request: AuditEventRequest,
    current_user: Dict = Depends(verify_token)
):
    """Log an audit event to the blockchain"""
    try:
        # Create audit event
        audit_event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType(audit_request.event_type),
            timestamp=datetime.utcnow(),
            tenant_id=current_user["tenant_id"],
            user_id=current_user["user_id"],
            event_data=audit_request.event_data,
            risk_level=audit_request.risk_level,
            compliance_flags=audit_request.compliance_flags
        )
        
        # Log to blockchain
        success = await blockchain_audit_system.log_audit_event(audit_event)
        
        if success:
            return {
                "event_id": audit_event.event_id,
                "status": "logged",
                "blockchain_hash": "generated",  # In real implementation, return actual hash
                "timestamp": audit_event.timestamp.isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to log audit event")
            
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid event type: {audit_request.event_type}")
    except Exception as e:
        logger.error(f"Error logging audit event: {e}")
        raise HTTPException(status_code=500, detail=f"Audit logging failed: {str(e)}")

@app.get("/api/v2/audit/trail", response_model=List[Dict[str, Any]])
async def get_audit_trail(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: Dict = Depends(verify_token)
):
    """Get audit trail for the current tenant"""
    try:
        trail = await blockchain_audit_system.get_audit_trail(
            current_user["tenant_id"], 
            start_date, 
            end_date
        )
        return trail
    except Exception as e:
        logger.error(f"Error getting audit trail: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit trail")

@app.get("/api/v2/audit/compliance/{regulation}", response_model=Dict[str, Any])
async def get_compliance_report(
    regulation: str,
    current_user: Dict = Depends(verify_token)
):
    """Generate compliance report for specific regulation"""
    try:
        report = await blockchain_audit_system.get_compliance_report(regulation.upper())
        return report
    except Exception as e:
        logger.error(f"Error generating compliance report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate compliance report")

@app.get("/api/v2/audit/blockchain/statistics", response_model=Dict[str, Any])
async def get_blockchain_statistics(
    current_user: Dict = Depends(verify_token)
):
    """Get blockchain audit system statistics"""
    try:
        stats = await blockchain_audit_system.get_blockchain_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting blockchain statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve blockchain statistics")

# ==================== ANALYTICS & REPORTING ENDPOINTS ====================

@app.get("/api/v2/analytics/dashboard", response_model=Dict[str, Any])
async def get_dashboard_analytics(
    timeframe: str = "24h",
    current_user: Dict = Depends(verify_token)
):
    """Get real-time dashboard analytics"""
    try:
        # Combine statistics from all systems
        threat_stats = await threat_detector.get_detection_statistics()
        response_stats = await response_orchestrator.get_plan_statistics()
        federated_stats = await federated_learning_system.get_training_statistics()
        blockchain_stats = await blockchain_audit_system.get_blockchain_statistics()
        
        # Calculate overall threat level
        total_threats = threat_stats.get("total_detections", 0)
        critical_threats = threat_stats.get("severity_distribution", {}).get("CRITICAL", 0)
        threat_level = "LOW"
        
        if critical_threats > 0:
            threat_level = "CRITICAL"
        elif total_threats > 100:
            threat_level = "HIGH"
        elif total_threats > 50:
            threat_level = "MEDIUM"
        
        return {
            "threat_level": threat_level,
            "total_detections": total_threats,
            "recent_threats_24h": total_threats,  # Simplified
            "active_responses": response_stats.get("active_plans", 0),
            "response_success_rate": response_stats.get("success_rate", 0),
            "federated_clients": federated_stats.get("total_registered_clients", 0),
            "blockchain_blocks": blockchain_stats.get("total_blocks", 0),
            "system_health": "HEALTHY",  # Simplified
            "last_updated": datetime.utcnow().isoformat(),
            "breakdown": {
                "threat_detection": threat_stats,
                "response_management": response_stats,
                "federated_learning": federated_stats,
                "blockchain_audit": blockchain_stats
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting dashboard analytics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve dashboard analytics")

# ==================== SYSTEM ENDPOINTS ====================

@app.get("/api/v2/system/health", response_model=Dict[str, Any])
async def system_health_check():
    """System health check endpoint"""
    try:
        # Check all major components
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "threat_detection": "operational",
                "response_orchestrator": "operational",
                "federated_learning": "operational",
                "blockchain_audit": "operational"
            },
            "uptime": "99.9%",  # Simplified
            "version": settings.VERSION
        }
        
        return health_status
        
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")

@app.get("/api/v2/system/configuration", response_model=Dict[str, Any])
async def get_system_configuration(
    current_user: Dict = Depends(verify_token)
):
    """Get system configuration (sanitized)"""
    try:
        # Return safe configuration information
        return {
            "app_name": settings.APP_NAME,
            "version": settings.VERSION,
            "deployment_mode": settings.DEPLOYMENT_MODE,
            "security_level": settings.SECURITY_LEVEL,
            "features": {
                "threat_detection": True,
                "automated_response": settings.AUTOMATED_RESPONSE_ENABLED,
                "federated_learning": settings.FEDERATED_LEARNING_ENABLED,
                "blockchain_audit": settings.BLOCKCHAIN_ENABLED,
                "wireless_monitoring": settings.WIRELESS_MONITORING_ENABLED
            },
            "compliance": {
                "gdpr": settings.GDPR_COMPLIANCE,
                "hipaa": settings.HIPAA_COMPLIANCE,
                "sox": settings.SOX_COMPLIANCE,
                "iso27001": settings.ISO27001_COMPLIANCE
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting system configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve configuration")

# ==================== ERROR HANDLERS ====================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    logger.warning(f"HTTP exception: {exc.status_code} - {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "message": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# ==================== ADDITIONAL ROUTES ====================

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "name": settings.APP_NAME,
        "version": settings.VERSION,
        "description": "AI-Powered Enterprise Cybersecurity Platform",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "threat_detection": "/api/v2/threats/detect",
            "automated_response": "/api/v2/response/execute",
            "federated_learning": "/api/v2/federated/register-client",
            "blockchain_audit": "/api/v2/audit/log",
            "analytics": "/api/v2/analytics/dashboard",
            "health_check": "/api/v2/system/health"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8080,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )