"""
NEXUS GUARD - Intelligent Response Orchestrator
Automated threat response and incident management system
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
import subprocess
import iptables
from pathlib import Path

from config import settings, SecurityLevel, SecurityConstants
from threat_detector import ThreatAnalysis, ThreatSeverity, ThreatType

logger = logging.getLogger(__name__)

class ResponseAction(str, Enum):
    """Available response actions"""
    MONITOR = "MONITOR"
    ALERT = "ALERT"
    ISOLATE = "ISOLATE"
    BLOCK_IP = "BLOCK_IP"
    BLOCK_PORT = "BLOCK_PORT"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    DISABLE_USER = "DISABLE_USER"
    SHUTDOWN_SERVICE = "SHUTDOWN_SERVICE"
    ACTIVATE_DDOS_PROTECTION = "ACTIVATE_DDOS_PROTECTION"
    ENABLE_LOGGING = "ENABLE_LOGGING"
    PRESERVE_FORENSICS = "PRESERVE_FORENSICS"
    NOTIFY_SOC = "NOTIFY_SOC"
    ESCALATE = "ESCALATE"

class ResponseStatus(str, Enum):
    """Response execution status"""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    CANCELLED = "CANCELLED"

@dataclass
class ResponseStep:
    """Individual response action step"""
    id: str
    action: ResponseAction
    parameters: Dict[str, Any]
    status: ResponseStatus = ResponseStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    rollback_action: Optional[ResponseAction] = None
    rollback_parameters: Optional[Dict[str, Any]] = None

@dataclass
class ResponsePlan:
    """Complete response plan for a threat"""
    id: str
    threat_analysis: ThreatAnalysis
    steps: List[ResponseStep]
    created_at: datetime
    priority: ThreatSeverity
    estimated_duration_minutes: int
    requires_approval: bool = False
    approved_by: Optional[str] = None
    approval_time: Optional[datetime] = None

class ResponseExecutor:
    """Base class for executing response actions"""
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the response action"""
        raise NotImplementedError
    
    async def rollback(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback the response action"""
        raise NotImplementedError

class IPBlockerExecutor(ResponseExecutor):
    """IP blocking response executor using iptables"""
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Block IP address using iptables"""
        ip_address = parameters.get('ip_address')
        duration = parameters.get('duration_minutes', 60)
        port = parameters.get('port')
        
        if not ip_address:
            raise ValueError("IP address is required")
        
        try:
            # Add iptables rule
            if port:
                cmd = f"iptables -A INPUT -s {ip_address} -p tcp --dport {port} -j DROP"
            else:
                cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Failed to block IP {ip_address}: {result.stderr}")
            
            # Schedule removal of rule
            await self._schedule_rule_removal(ip_address, port, duration)
            
            logger.info(f"Blocked IP {ip_address} for {duration} minutes")
            
            return {
                "success": True,
                "blocked_ip": ip_address,
                "blocked_port": port,
                "duration_minutes": duration,
                "command_executed": cmd
            }
            
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            raise
    
    async def rollback(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove IP block rule"""
        ip_address = parameters.get('ip_address')
        port = parameters.get('port')
        
        try:
            # Remove iptables rule
            if port:
                cmd = f"iptables -D INPUT -s {ip_address} -p tcp --dport {port} -j DROP"
            else:
                cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.warning(f"Failed to remove block rule for {ip_address}: {result.stderr}")
            
            logger.info(f"Removed block rule for IP {ip_address}")
            
            return {
                "success": True,
                "unblocked_ip": ip_address,
                "command_executed": cmd
            }
            
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            raise
    
    async def _schedule_rule_removal(self, ip_address: str, port: Optional[int], duration: int):
        """Schedule automatic removal of blocking rule"""
        # In a real implementation, this would use a job scheduler
        # For now, we'll just log it
        logger.info(f"Scheduled removal of block rule for {ip_address} in {duration} minutes")

class SystemIsolationExecutor(ResponseExecutor):
    """System isolation response executor"""
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Isolate affected system"""
        system_id = parameters.get('system_id')
        isolation_type = parameters.get('isolation_type', 'network')
        
        if not system_id:
            raise ValueError("System ID is required")
        
        try:
            if isolation_type == 'network':
                # Disconnect from network
                result = await self._disconnect_from_network(system_id)
            elif isolation_type == 'quarantine':
                # Move to quarantine network
                result = await self._move_to_quarantine(system_id)
            elif isolation_type == 'complete':
                # Complete system isolation
                result = await self._complete_isolation(system_id)
            else:
                raise ValueError(f"Unknown isolation type: {isolation_type}")
            
            logger.info(f"Isolated system {system_id} using {isolation_type} isolation")
            
            return {
                "success": True,
                "system_id": system_id,
                "isolation_type": isolation_type,
                "isolation_result": result
            }
            
        except Exception as e:
            logger.error(f"Error isolating system {system_id}: {e}")
            raise
    
    async def rollback(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restore system connectivity"""
        system_id = parameters.get('system_id')
        
        try:
            # Restore network connectivity
            result = await self._restore_network_connectivity(system_id)
            
            logger.info(f"Restored connectivity for system {system_id}")
            
            return {
                "success": True,
                "system_id": system_id,
                "restoration_result": result
            }
            
        except Exception as e:
            logger.error(f"Error restoring connectivity for {system_id}: {e}")
            raise
    
    async def _disconnect_from_network(self, system_id: str) -> Dict[str, Any]:
        """Disconnect system from network"""
        # Placeholder implementation
        return {"action": "network_disconnect", "system_id": system_id}
    
    async def _move_to_quarantine(self, system_id: str) -> Dict[str, Any]:
        """Move system to quarantine network"""
        # Placeholder implementation
        return {"action": "quarantine_move", "system_id": system_id}
    
    async def _complete_isolation(self, system_id: str) -> Dict[str, Any]:
        """Completely isolate system"""
        # Placeholder implementation
        return {"action": "complete_isolation", "system_id": system_id}
    
    async def _restore_network_connectivity(self, system_id: str) -> Dict[str, Any]:
        """Restore system network connectivity"""
        # Placeholder implementation
        return {"action": "network_restore", "system_id": system_id}

class UserAccountExecutor(ResponseExecutor):
    """User account management response executor"""
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute user account action"""
        user_id = parameters.get('user_id')
        action = parameters.get('action')  # 'disable', 'reset_password', 'force_logout'
        
        if not user_id:
            raise ValueError("User ID is required")
        
        try:
            if action == 'disable':
                result = await self._disable_user(user_id)
            elif action == 'reset_password':
                result = await self._reset_user_password(user_id)
            elif action == 'force_logout':
                result = await self._force_user_logout(user_id)
            else:
                raise ValueError(f"Unknown user action: {action}")
            
            logger.info(f"Executed {action} for user {user_id}")
            
            return {
                "success": True,
                "user_id": user_id,
                "action": action,
                "result": result
            }
            
        except Exception as e:
            logger.error(f"Error executing {action} for user {user_id}: {e}")
            raise
    
    async def rollback(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback user account action"""
        user_id = parameters.get('user_id')
        original_action = parameters.get('action')
        
        try:
            if original_action == 'disable':
                result = await self._enable_user(user_id)
            elif original_action == 'reset_password':
                result = await self._restore_user_password(user_id)
            elif original_action == 'force_logout':
                # No rollback needed for logout
                result = {"action": "no_rollback_needed"}
            
            logger.info(f"Rolled back {original_action} for user {user_id}")
            
            return {
                "success": True,
                "user_id": user_id,
                "rollback_action": original_action,
                "result": result
            }
            
        except Exception as e:
            logger.error(f"Error rolling back {original_action} for user {user_id}: {e}")
            raise
    
    async def _disable_user(self, user_id: str) -> Dict[str, Any]:
        """Disable user account"""
        # Placeholder implementation
        return {"action": "disable_user", "user_id": user_id, "status": "disabled"}
    
    async def _enable_user(self, user_id: str) -> Dict[str, Any]:
        """Enable user account"""
        # Placeholder implementation
        return {"action": "enable_user", "user_id": user_id, "status": "enabled"}
    
    async def _reset_user_password(self, user_id: str) -> Dict[str, Any]:
        """Reset user password"""
        # Placeholder implementation
        return {"action": "reset_password", "user_id": user_id, "status": "password_reset"}
    
    async def _restore_user_password(self, user_id: str) -> Dict[str, Any]:
        """Restore user password"""
        # Placeholder implementation
        return {"action": "restore_password", "user_id": user_id, "status": "password_restored"}
    
    async def _force_user_logout(self, user_id: str) -> Dict[str, Any]:
        """Force user logout"""
        # Placeholder implementation
        return {"action": "force_logout", "user_id": user_id, "status": "logged_out"}

class NotificationExecutor(ResponseExecutor):
    """Notification and alerting response executor"""
    
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Send notifications"""
        notification_type = parameters.get('type', 'security_alert')
        recipients = parameters.get('recipients', [])
        message = parameters.get('message', '')
        priority = parameters.get('priority', 'HIGH')
        
        try:
            # Send different types of notifications
            if notification_type == 'security_alert':
                result = await self._send_security_alert(recipients, message, priority)
            elif notification_type == 'soc_notification':
                result = await self._send_soc_notification(recipients, message, priority)
            elif notification_type == 'escalation':
                result = await self._send_escalation(recipients, message, priority)
            else:
                raise ValueError(f"Unknown notification type: {notification_type}")
            
            logger.info(f"Sent {notification_type} notification to {len(recipients)} recipients")
            
            return {
                "success": True,
                "notification_type": notification_type,
                "recipients_count": len(recipients),
                "result": result
            }
            
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
            raise
    
    async def rollback(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback notification (essentially a no-op)"""
        return {
            "success": True,
            "message": "Notification rollback - no action needed"
        }
    
    async def _send_security_alert(self, recipients: List[str], message: str, priority: str) -> Dict[str, Any]:
        """Send security alert"""
        # Placeholder implementation
        return {"action": "security_alert", "recipients": recipients, "priority": priority}
    
    async def _send_soc_notification(self, recipients: List[str], message: str, priority: str) -> Dict[str, Any]:
        """Send SOC notification"""
        # Placeholder implementation
        return {"action": "soc_notification", "recipients": recipients, "priority": priority}
    
    async def _send_escalation(self, recipients: List[str], message: str, priority: str) -> Dict[str, Any]:
        """Send escalation notification"""
        # Placeholder implementation
        return {"action": "escalation", "recipients": recipients, "priority": priority}

class ResponseOrchestrator:
    """Main response orchestration system"""
    
    def __init__(self):
        self.response_strategies = {
            ThreatSeverity.CRITICAL: self._critical_response_strategy,
            ThreatSeverity.HIGH: self._high_response_strategy,
            ThreatSeverity.MEDIUM: self._medium_response_strategy,
            ThreatSeverity.LOW: self._low_response_strategy,
            ThreatSeverity.INFO: self._info_response_strategy
        }
        
        self.executors = {
            ResponseAction.BLOCK_IP: IPBlockerExecutor(),
            ResponseAction.BLOCK_PORT: IPBlockerExecutor(),
            ResponseAction.ISOLATE: SystemIsolationExecutor(),
            ResponseAction.DISABLE_USER: UserAccountExecutor(),
            ResponseAction.NOTIFY_SOC: NotificationExecutor(),
            ResponseAction.ESCALATE: NotificationExecutor()
        }
        
        self.active_plans = {}
        self.plan_history = []
        
    async def generate_response_plan(self, threat_analysis: ThreatAnalysis) -> ResponsePlan:
        """Generate appropriate response plan based on threat analysis"""
        strategy = self.response_strategies.get(threat_analysis.severity, self._info_response_strategy)
        
        # Generate plan using the appropriate strategy
        steps = await strategy(threat_analysis)
        
        # Create response plan
        plan = ResponsePlan(
            id=str(uuid.uuid4()),
            threat_analysis=threat_analysis,
            steps=steps,
            created_at=datetime.utcnow(),
            priority=threat_analysis.severity,
            estimated_duration_minutes=sum(step.get('estimated_duration', 5) for step in steps),
            requires_approval=threat_analysis.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH] and 
                           settings.HUMAN_VERIFICATION_REQUIRED
        )
        
        return plan
    
    async def execute_response_plan(self, plan: ResponsePlan, approved_by: Optional[str] = None) -> Dict[str, Any]:
        """Execute the response plan"""
        if plan.requires_approval and not approved_by:
            raise ValueError("Plan requires approval but no approver specified")
        
        # Mark plan as approved
        if approved_by:
            plan.approved_by = approved_by
            plan.approval_time = datetime.utcnow()
        
        self.active_plans[plan.id] = plan
        
        execution_results = []
        
        try:
            # Execute each step in the plan
            for step in plan.steps:
                try:
                    await self._execute_step(step)
                    execution_results.append({
                        "step_id": step.id,
                        "status": "success",
                        "result": step.result
                    })
                except Exception as e:
                    step.status = ResponseStatus.FAILED
                    step.error_message = str(e)
                    execution_results.append({
                        "step_id": step.id,
                        "status": "failed",
                        "error": str(e)
                    })
                    
                    # Decide whether to continue or stop based on failure severity
                    if self._should_stop_on_failure(step):
                        break
            
            # Move plan to history
            self.plan_history.append(plan)
            if plan.id in self.active_plans:
                del self.active_plans[plan.id]
            
            return {
                "plan_id": plan.id,
                "execution_results": execution_results,
                "completed_steps": len([r for r in execution_results if r["status"] == "success"]),
                "failed_steps": len([r for r in execution_results if r["status"] == "failed"])
            }
            
        except Exception as e:
            logger.error(f"Error executing response plan {plan.id}: {e}")
            raise
    
    async def _execute_step(self, step: ResponseStep):
        """Execute individual response step"""
        step.status = ResponseStatus.IN_PROGRESS
        step.start_time = datetime.utcnow()
        
        try:
            # Get the appropriate executor
            executor = self.executors.get(step.action)
            if not executor:
                raise ValueError(f"No executor found for action: {step.action}")
            
            # Execute the action
            result = await executor.execute(step.parameters)
            
            # Update step status
            step.status = ResponseStatus.COMPLETED
            step.end_time = datetime.utcnow()
            step.result = result
            
        except Exception as e:
            step.status = ResponseStatus.FAILED
            step.end_time = datetime.utcnow()
            step.error_message = str(e)
            raise
    
    async def rollback_response_plan(self, plan_id: str) -> Dict[str, Any]:
        """Rollback a completed or failed response plan"""
        if plan_id not in self.plan_history:
            raise ValueError(f"Plan {plan_id} not found in history")
        
        # Find the plan
        plan = next((p for p in self.plan_history if p.id == plan_id), None)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")
        
        rollback_results = []
        
        try:
            # Execute rollback steps in reverse order
            for step in reversed(plan.steps):
                if step.status == ResponseStatus.COMPLETED and step.rollback_action:
                    try:
                        await self._rollback_step(step)
                        rollback_results.append({
                            "step_id": step.id,
                            "rollback_status": "success"
                        })
                    except Exception as e:
                        rollback_results.append({
                            "step_id": step.id,
                            "rollback_status": "failed",
                            "error": str(e)
                        })
            
            # Update plan status
            for step in plan.steps:
                if step.status == ResponseStatus.COMPLETED:
                    step.status = ResponseStatus.ROLLED_BACK
            
            return {
                "plan_id": plan_id,
                "rollback_results": rollback_results,
                "rolled_back_steps": len([r for r in rollback_results if r["rollback_status"] == "success"])
            }
            
        except Exception as e:
            logger.error(f"Error rolling back plan {plan_id}: {e}")
            raise
    
    async def _rollback_step(self, step: ResponseStep):
        """Rollback individual step"""
        if not step.rollback_action:
            return
        
        # Get the appropriate executor
        executor = self.executors.get(step.rollback_action)
        if not executor:
            raise ValueError(f"No executor found for rollback action: {step.rollback_action}")
        
        rollback_params = step.rollback_parameters or step.parameters
        await executor.rollback(rollback_params)
    
    def _should_stop_on_failure(self, step: ResponseStep) -> bool:
        """Determine if plan execution should stop on step failure"""
        # Critical actions should stop on failure
        critical_actions = [
            ResponseAction.ISOLATE,
            ResponseAction.BLOCK_IP,
            ResponseAction.DISABLE_USER,
            ResponseAction.SHUTDOWN_SERVICE
        ]
        return step.action in critical_actions
    
    # Response strategies for different threat severities
    
    async def _critical_response_strategy(self, threat_analysis: ThreatAnalysis) -> List[Dict[str, Any]]:
        """Critical threat response strategy"""
        steps = []
        
        # Immediate containment
        if threat_analysis.threat_type in [ThreatType.RANSOMWARE, ThreatType.APT]:
            steps.append({
                "id": str(uuid.uuid4()),
                "action": ResponseAction.ISOLATE,
                "parameters": {
                    "system_id": threat_analysis.event_id,
                    "isolation_type": "complete"
                },
                "estimated_duration": 2,
                "rollback_action": ResponseAction.ISOLATE,
                "rollback_parameters": {
                    "action": "restore_connectivity"
                }
            })
        
        # Block attacking IP
        if threat_analysis.analysis_details.get('source_ip'):
            steps.append({
                "id": str(uuid.uuid4()),
                "action": ResponseAction.BLOCK_IP,
                "parameters": {
                    "ip_address": threat_analysis.analysis_details['source_ip'],
                    "duration_minutes": 1440  # 24 hours
                },
                "estimated_duration": 1,
                "rollback_action": ResponseAction.BLOCK_IP
            })
        
        # Immediate SOC notification
        steps.append({
            "id": str(uuid.uuid4()),
            "action": ResponseAction.NOTIFY_SOC,
            "parameters": {
                "type": "security_alert",
                "recipients": ["soc-team@company.com"],
                "message": f"CRITICAL: {threat_analysis.threat_type} detected",
                "priority": "CRITICAL"
            },
            "estimated_duration": 1
        })
        
        # Preserve forensics
        steps.append({
            "id": str(uuid.uuid4()),
            "action": ResponseAction.PRESERVE_FORENSICS,
            "parameters": {
                "system_id": threat_analysis.event_id,
                "preserve_duration_hours": 168  # 7 days
            },
            "estimated_duration": 30
        })
        
        # Escalate to management
        steps.append({
            "id": str(uuid.uuid4()),
            "action": ResponseAction.ESCALATE,
            "parameters": {
                "type": "escalation",
                "recipients": ["security-director@company.com", "cto@company.com"],
                "message": f"CRITICAL security incident: {threat_analysis.threat_type}",
                "priority": "CRITICAL"
            },
            "estimated_duration": 2
        })
        
        return steps
    
    async def _high_response_strategy(self, threat_analysis: ThreatAnalysis) -> List[Dict[str, Any]]:
        """High threat response strategy"""
        steps = []
        
        # Enhanced monitoring
        steps.append({
            "id": str(uuid.uuid4()),
            "action": ResponseAction.ENABLE_LOGGING,
            "parameters": {
                "system_id": threat_analysis.event_id,
                "log_level": "DEBUG",
                "duration_hours": 24
            },
            "estimated_duration": 5
        })
        
        # Block if specific indicators
        if threat_analysis.indicators:
            steps.append({
                "id": str(uuid.uuid4()),
                "action": ResponseAction.BLOCK_IP,
                "parameters": {
                    "ip_address": threat_analysis.analysis_details.get('source_ip'),
                    "duration_minutes": 480  # 8 hours
                },
                "estimated_duration": 2
            })
        
        # SOC notification
        steps.append({
            "id": str(uuid.uuid4()),
            "action": ResponseAction.NOTIFY_SOC,
            "parameters": {
                "type": "soc_notification",
                "recipients": ["soc-team@company.com"],
                "message": f"HIGH: {threat_analysis.threat_type} detected",
                "priority": "HIGH"
            },
            "estimated_duration": 2
        })
        
        return steps
    
    async def _medium_response_strategy(self, threat_analysis: ThreatAnalysis) -> List[Dict[str, Any]]:
        """Medium threat response strategy"""
        steps = []
        
        # Increase monitoring
        steps.append({
            "id": str(uuid.uuid4()),
            "action": ResponseAction.ENABLE_LOGGING,
            "parameters": {
                "system_id": threat_analysis.event_id,
                "log_level": "INFO",
                "duration_hours": 12
            },
            "estimated_duration": 3
        })
        
        # Alert security team
        steps.append({
            "id": str(uuid.uuid4()),
            "action": ResponseAction.ALERT,
            "parameters": {
                "alert_type": "medium_threat",
                "message": f"MEDIUM: {threat_analysis.threat_type} detected",
                "recipients": ["security-team@company.com"]
            },
            "estimated_duration": 1
        })
        
        return steps
    
    async def _low_response_strategy(self, threat_analysis: ThreatAnalysis) -> List[Dict[str, Any]]:
        """Low threat response strategy"""
        steps = []
        
        # Continue monitoring
        steps.append({
            "id": str(uuid.uuid4()),
            "action": ResponseAction.MONITOR,
            "parameters": {
                "system_id": threat_analysis.event_id,
                "monitoring_duration_hours": 4
            },
            "estimated_duration": 1
        })
        
        return steps
    
    async def _info_response_strategy(self, threat_analysis: ThreatAnalysis) -> List[Dict[str, Any]]:
        """Info-level threat response strategy"""
        steps = []
        
        # Log for trend analysis
        steps.append({
            "id": str(uuid.uuid4()),
            "action": ResponseAction.MONITOR,
            "parameters": {
                "system_id": threat_analysis.event_id,
                "log_only": True
            },
            "estimated_duration": 1
        })
        
        return steps
    
    async def get_active_plans(self) -> List[Dict[str, Any]]:
        """Get all active response plans"""
        return [asdict(plan) for plan in self.active_plans.values()]
    
    async def get_plan_statistics(self) -> Dict[str, Any]:
        """Get response plan statistics"""
        if not self.plan_history:
            return {"status": "no_data"}
        
        total_plans = len(self.plan_history)
        
        # Success rate
        successful_plans = sum(1 for plan in self.plan_history 
                             if all(step.status == ResponseStatus.COMPLETED for step in plan.steps))
        success_rate = successful_plans / total_plans
        
        # Average execution time
        execution_times = []
        for plan in self.plan_history:
            if plan.steps:
                first_start = min(step.start_time for step in plan.steps if step.start_time)
                last_end = max(step.end_time for step in plan.steps if step.end_time)
                if first_start and last_end:
                    execution_time = (last_end - first_start).total_seconds() / 60
                    execution_times.append(execution_time)
        
        avg_execution_time = sum(execution_times) / len(execution_times) if execution_times else 0
        
        return {
            "total_plans": total_plans,
            "success_rate": success_rate,
            "average_execution_time_minutes": avg_execution_time,
            "active_plans": len(self.active_plans),
            "total_rollback_count": sum(1 for plan in self.plan_history 
                                      if any(step.status == ResponseStatus.ROLLED_BACK for step in plan.steps))
        }

# Global response orchestrator instance
response_orchestrator = ResponseOrchestrator()