#!/usr/bin/env python3
"""
NEXUS GUARD - Comprehensive Testing and Deployment Script
Tests all components of the cybersecurity platform
"""

import asyncio
import requests
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
import sys
import os

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app
    from threat_detector import ThreatEvent, ThreatType, ThreatSeverity
    from response_orchestrator import ResponsePlan
    from federated_learning import ClientNode, ModelType
    from blockchain_audit import AuditEvent, AuditEventType
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Please ensure all modules are properly installed")
    sys.exit(1)

class NexusGuardTester:
    """Comprehensive testing suite for NEXUS GUARD"""
    
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.test_results = []
        self.test_tokens = []
        
    def log_test(self, test_name: str, status: str, details: str = "", duration: float = 0):
        """Log test result"""
        result = {
            "test_name": test_name,
            "status": status,
            "details": details,
            "duration": duration,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.test_results.append(result)
        
        # Print result
        status_symbol = "✅" if status == "PASS" else "❌"
        print(f"{status_symbol} {test_name}: {status}")
        if details:
            print(f"   📝 {details}")
        print(f"   ⏱️  Duration: {duration:.2f}s")
    
    async def test_system_health(self) -> bool:
        """Test system health endpoint"""
        test_name = "System Health Check"
        start_time = time.time()
        
        try:
            response = requests.get(f"{self.base_url}/api/v2/system/health", timeout=10)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                health_data = response.json()
                if health_data.get("status") == "healthy":
                    self.log_test(test_name, "PASS", "System is healthy", duration)
                    return True
                else:
                    self.log_test(test_name, "FAIL", f"System status: {health_data.get('status')}", duration)
                    return False
            else:
                self.log_test(test_name, "FAIL", f"HTTP {response.status_code}", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test(test_name, "FAIL", f"Connection error: {str(e)}", duration)
            return False
    
    async def test_threat_detection(self) -> bool:
        """Test threat detection system"""
        test_name = "Threat Detection System"
        start_time = time.time()
        
        try:
            # Create test threat events
            threat_events = [
                {
                    "source_ip": "192.168.1.100",
                    "destination_ip": "10.0.0.1",
                    "event_type": "NETWORK_SCAN",
                    "protocol": "TCP",
                    "port": 22,
                    "payload": "",
                    "metadata": {"frequency": 100, "unusual": True}
                },
                {
                    "source_ip": "192.168.1.101",
                    "destination_ip": "10.0.0.2",
                    "event_type": "MALWARE_DOWNLOAD",
                    "protocol": "HTTP",
                    "port": 80,
                    "payload": "cHV0IG1hbHdhcmUgaGVyZQ==",
                    "metadata": {"file_size": 1024000, "suspicious": True}
                },
                {
                    "source_ip": "192.168.1.102",
                    "destination_ip": "10.0.0.3",
                    "event_type": "NORMAL_BROWSING",
                    "protocol": "HTTPS",
                    "port": 443,
                    "payload": "",
                    "metadata": {"frequency": 5, "normal": True}
                }
            ]
            
            successful_detections = 0
            
            for i, event_data in enumerate(threat_events):
                try:
                    response = requests.post(
                        f"{self.base_url}/api/v2/threats/detect",
                        json=event_data,
                        headers={"Authorization": "Bearer test_token"},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if "threat_type" in result and "severity" in result:
                            successful_detections += 1
                            print(f"   🔍 Detection {i+1}: {result['threat_type']} ({result['severity']})")
                    else:
                        print(f"   ❌ Detection {i+1} failed: HTTP {response.status_code}")
                        
                except Exception as e:
                    print(f"   ❌ Detection {i+1} error: {str(e)}")
            
            duration = time.time() - start_time
            
            if successful_detections == len(threat_events):
                self.log_test(test_name, "PASS", f"All {successful_detections} threat events processed", duration)
                return True
            else:
                self.log_test(test_name, "FAIL", f"Only {successful_detections}/{len(threat_events)} events processed", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test(test_name, "FAIL", f"System error: {str(e)}", duration)
            return False
    
    async def test_automated_response(self) -> bool:
        """Test automated response system"""
        test_name = "Automated Response System"
        start_time = time.time()
        
        try:
            # Create a mock threat analysis
            threat_analysis = {
                "threat_id": str(uuid.uuid4()),
                "threat_type": "MALWARE",
                "severity": "HIGH",
                "confidence_score": 0.92,
                "indicators": ["ANOMALY_DETECTED", "SUSPICIOUS_PAYLOAD"],
                "recommended_actions": ["ISOLATE_SYSTEM", "BLOCK_IP", "NOTIFY_SOC"],
                "auto_response_required": True
            }
            
            # Request response execution
            response = requests.post(
                f"{self.base_url}/api/v2/response/execute",
                json={
                    "threat_analysis": threat_analysis,
                    "approved_by": "test_analyst"
                },
                headers={"Authorization": "Bearer test_token"},
                timeout=10
            )
            
            duration = time.time() - start_time
            
            if response.status_code == 200:
                result = response.json()
                if "plan_id" in result and "execution_result" in result:
                    self.log_test(test_name, "PASS", f"Response plan executed: {result['plan_id']}", duration)
                    return True
                else:
                    self.log_test(test_name, "FAIL", "Invalid response format", duration)
                    return False
            else:
                self.log_test(test_name, "FAIL", f"HTTP {response.status_code}: {response.text}", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test(test_name, "FAIL", f"System error: {str(e)}", duration)
            return False
    
    async def test_blockchain_audit(self) -> bool:
        """Test blockchain audit system"""
        test_name = "Blockchain Audit System"
        start_time = time.time()
        
        try:
            # Log various audit events
            audit_events = [
                {
                    "event_type": "USER_ACCESS",
                    "event_data": {"user_id": "test_user", "action": "LOGIN"},
                    "risk_level": "LOW",
                    "compliance_flags": ["ISO27001"]
                },
                {
                    "event_type": "THREAT_DETECTED",
                    "event_data": {"threat_id": "test_threat", "severity": "MEDIUM"},
                    "risk_level": "MEDIUM",
                    "compliance_flags": ["ISO27001", "GDPR"]
                },
                {
                    "event_type": "SYSTEM_CONFIGURATION",
                    "event_data": {"action": "CONFIG_UPDATE", "parameter": "threshold"},
                    "risk_level": "INFO",
                    "compliance_flags": []
                }
            ]
            
            successful_logs = 0
            
            for i, event_data in enumerate(audit_events):
                try:
                    response = requests.post(
                        f"{self.base_url}/api/v2/audit/log",
                        json=event_data,
                        headers={"Authorization": "Bearer test_token"},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if "event_id" in result:
                            successful_logs += 1
                            print(f"   📝 Audit event {i+1} logged: {result['event_id']}")
                    else:
                        print(f"   ❌ Audit event {i+1} failed: HTTP {response.status_code}")
                        
                except Exception as e:
                    print(f"   ❌ Audit event {i+1} error: {str(e)}")
            
            duration = time.time() - start_time
            
            if successful_logs == len(audit_events):
                self.log_test(test_name, "PASS", f"All {successful_logs} audit events logged", duration)
                
                # Test audit trail retrieval
                try:
                    trail_response = requests.get(
                        f"{self.base_url}/api/v2/audit/trail",
                        headers={"Authorization": "Bearer test_token"},
                        timeout=5
                    )
                    
                    if trail_response.status_code == 200:
                        trail_data = trail_response.json()
                        print(f"   📊 Retrieved {len(trail_data)} audit trail entries")
                    else:
                        print(f"   ⚠️  Audit trail retrieval failed: HTTP {trail_response.status_code}")
                        
                except Exception as e:
                    print(f"   ⚠️  Audit trail error: {str(e)}")
                
                return True
            else:
                self.log_test(test_name, "FAIL", f"Only {successful_logs}/{len(audit_events)} events logged", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test(test_name, "FAIL", f"System error: {str(e)}", duration)
            return False
    
    async def test_analytics_dashboard(self) -> bool:
        """Test analytics dashboard"""
        test_name = "Analytics Dashboard"
        start_time = time.time()
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v2/analytics/dashboard",
                headers={"Authorization": "Bearer test_token"},
                timeout=10
            )
            
            duration = time.time() - start_time
            
            if response.status_code == 200:
                dashboard_data = response.json()
                
                # Check required dashboard fields
                required_fields = ["threat_level", "total_detections", "system_health"]
                missing_fields = [field for field in required_fields if field not in dashboard_data]
                
                if not missing_fields:
                    self.log_test(
                        test_name, 
                        "PASS", 
                        f"Threat Level: {dashboard_data['threat_level']}, Detections: {dashboard_data['total_detections']}", 
                        duration
                    )
                    return True
                else:
                    self.log_test(test_name, "FAIL", f"Missing fields: {missing_fields}", duration)
                    return False
            else:
                self.log_test(test_name, "FAIL", f"HTTP {response.status_code}", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test(test_name, "FAIL", f"System error: {str(e)}", duration)
            return False
    
    async def test_federated_learning(self) -> bool:
        """Test federated learning system"""
        test_name = "Federated Learning System"
        start_time = time.time()
        
        try:
            # Test client registration
            client_data = {
                "organization_id": "test_org",
                "role": "DATA_OWNER",
                "public_key": "test_public_key_base64"
            }
            
            response = requests.post(
                f"{self.base_url}/api/v2/federated/register-client",
                json=client_data,
                headers={"Authorization": "Bearer test_token"},
                timeout=5
            )
            
            duration = time.time() - start_time
            
            if response.status_code == 200:
                result = response.json()
                if "client_id" in result:
                    self.log_test(test_name, "PASS", f"Client registered: {result['client_id']}", duration)
                    return True
                else:
                    self.log_test(test_name, "FAIL", "Invalid registration response", duration)
                    return False
            else:
                self.log_test(test_name, "FAIL", f"HTTP {response.status_code}", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test(test_name, "FAIL", f"System error: {str(e)}", duration)
            return False
    
    async def test_performance_load(self) -> bool:
        """Test system performance under load"""
        test_name = "Performance Load Test"
        start_time = time.time()
        
        try:
            # Create multiple concurrent threat detection requests
            import concurrent.futures
            import threading
            
            def send_threat_request(request_id):
                event_data = {
                    "source_ip": f"192.168.1.{100 + request_id % 50}",
                    "destination_ip": "10.0.0.1",
                    "event_type": "LOAD_TEST",
                    "protocol": "TCP",
                    "port": 80,
                    "payload": "",
                    "metadata": {"request_id": request_id}
                }
                
                try:
                    response = requests.post(
                        f"{self.base_url}/api/v2/threats/detect",
                        json=event_data,
                        headers={"Authorization": "Bearer test_token"},
                        timeout=5
                    )
                    return response.status_code == 200
                except:
                    return False
            
            # Send 50 concurrent requests
            num_requests = 50
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(send_threat_request, i) for i in range(num_requests)]
                results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
            duration = time.time() - start_time
            successful_requests = sum(results)
            
            if successful_requests >= num_requests * 0.9:  # 90% success rate
                self.log_test(
                    test_name, 
                    "PASS", 
                    f"{successful_requests}/{num_requests} requests successful", 
                    duration
                )
                return True
            else:
                self.log_test(
                    test_name, 
                    "FAIL", 
                    f"Only {successful_requests}/{num_requests} requests successful", 
                    duration
                )
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test(test_name, "FAIL", f"Load test error: {str(e)}", duration)
            return False
    
    async def test_integration_scenarios(self) -> bool:
        """Test complete integration scenarios"""
        test_name = "Integration Scenarios"
        start_time = time.time()
        
        try:
            scenario_results = []
            
            # Scenario 1: Threat Detection -> Response -> Audit
            print("   🔄 Testing complete threat scenario...")
            
            # Detect threat
            threat_response = requests.post(
                f"{self.base_url}/api/v2/threats/detect",
                json={
                    "source_ip": "192.168.1.200",
                    "destination_ip": "10.0.0.10",
                    "event_type": "ADVANCED_THREAT",
                    "protocol": "TCP",
                    "port": 443,
                    "payload": "",
                    "metadata": {"severity": "high", "attack_type": "apt"}
                },
                headers={"Authorization": "Bearer test_token"},
                timeout=5
            )
            
            if threat_response.status_code == 200:
                threat_data = threat_response.json()
                
                # Execute response
                response = requests.post(
                    f"{self.base_url}/api/v2/response/execute",
                    json={
                        "threat_analysis": threat_data,
                        "approved_by": "integration_test"
                    },
                    headers={"Authorization": "Bearer test_token"},
                    timeout=10
                )
                
                if response.status_code == 200:
                    scenario_results.append(True)
                    print("   ✅ Complete threat scenario successful")
                else:
                    scenario_results.append(False)
                    print("   ❌ Response execution failed")
            else:
                scenario_results.append(False)
                print("   ❌ Threat detection failed")
            
            duration = time.time() - start_time
            
            if all(scenario_results):
                self.log_test(test_name, "PASS", "All integration scenarios passed", duration)
                return True
            else:
                self.log_test(test_name, "FAIL", "Some integration scenarios failed", duration)
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_test(test_name, "FAIL", f"Integration test error: {str(e)}", duration)
            return False
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests and return results"""
        print("🛡️  NEXUS GUARD - Comprehensive Test Suite")
        print("=" * 60)
        
        test_methods = [
            self.test_system_health,
            self.test_threat_detection,
            self.test_automated_response,
            self.test_blockchain_audit,
            self.test_analytics_dashboard,
            self.test_federated_learning,
            self.test_performance_load,
            self.test_integration_scenarios
        ]
        
        print(f"🔍 Running {len(test_methods)} test suites...\n")
        
        for i, test_method in enumerate(test_methods, 1):
            print(f"📋 Test Suite {i}/{len(test_methods)}: {test_method.__name__.replace('test_', '').replace('_', ' ').title()}")
            try:
                await test_method()
            except Exception as e:
                print(f"❌ Test suite {i} failed with exception: {str(e)}")
            print()
        
        return self.generate_test_report()
    
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["status"] == "PASS")
        failed_tests = total_tests - passed_tests
        pass_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        avg_duration = sum(result["duration"] for result in self.test_results) / total_tests if total_tests > 0 else 0
        
        report = {
            "summary": {
                "total_tests": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "pass_rate": pass_rate,
                "average_duration": avg_duration,
                "test_timestamp": datetime.utcnow().isoformat()
            },
            "detailed_results": self.test_results,
            "recommendations": self.get_recommendations()
        }
        
        return report
    
    def get_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        # Analyze failed tests
        failed_tests = [result for result in self.test_results if result["status"] == "FAIL"]
        
        if failed_tests:
            recommendations.append("Review and fix failed test cases")
            
            for test in failed_tests:
                if "health" in test["test_name"].lower():
                    recommendations.append("Check system health and service dependencies")
                elif "threat" in test["test_name"].lower():
                    recommendations.append("Verify threat detection models and configurations")
                elif "response" in test["test_name"].lower():
                    recommendations.append("Check response orchestration and execution")
                elif "blockchain" in test["test_name"].lower():
                    recommendations.append("Verify blockchain audit system status")
                elif "performance" in test["test_name"].lower():
                    recommendations.append("Optimize system performance and resources")
        
        # Performance recommendations
        avg_duration = sum(result["duration"] for result in self.test_results) / len(self.test_results)
        if avg_duration > 5.0:
            recommendations.append("Consider optimizing system performance - average response time > 5s")
        
        # Security recommendations
        recommendations.extend([
            "Ensure all API endpoints have proper authentication",
            "Verify SSL/TLS certificates are properly configured",
            "Review and update security configurations",
            "Monitor system logs for security events",
            "Regular backup of configuration and data"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def print_summary(self, report: Dict[str, Any]):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        summary = report["summary"]
        print(f"📋 Total Tests: {summary['total_tests']}")
        print(f"✅ Passed: {summary['passed']}")
        print(f"❌ Failed: {summary['failed']}")
        print(f"📈 Pass Rate: {summary['pass_rate']:.1f}%")
        print(f"⏱️  Average Duration: {summary['average_duration']:.2f}s")
        
        if summary['failed'] > 0:
            print(f"\n⚠️  FAILED TESTS:")
            for result in self.test_results:
                if result["status"] == "FAIL":
                    print(f"   • {result['test_name']}: {result['details']}")
        
        print(f"\n💡 RECOMMENDATIONS:")
        for i, recommendation in enumerate(report["recommendations"], 1):
            print(f"   {i}. {recommendation}")
        
        # Overall status
        if summary['pass_rate'] >= 90:
            print(f"\n🎉 OVERALL STATUS: EXCELLENT - System is production ready!")
        elif summary['pass_rate'] >= 70:
            print(f"\n⚠️  OVERALL STATUS: GOOD - Minor issues to address")
        else:
            print(f"\n🚨 OVERALL STATUS: NEEDS ATTENTION - Major issues found")

def main():
    """Main function to run tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NEXUS GUARD Test Suite")
    parser.add_argument("--url", default="http://localhost:8080", help="Base URL for testing")
    parser.add_argument("--save-report", help="Save test report to file")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Create tester
    tester = NexusGuardTester(args.url)
    
    async def run_tests():
        report = await tester.run_all_tests()
        tester.print_summary(report)
        
        # Save report if requested
        if args.save_report:
            with open(args.save_report, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📁 Test report saved to: {args.save_report}")
        
        # Return exit code based on results
        return 0 if report['summary']['pass_rate'] >= 70 else 1
    
    # Run tests
    exit_code = asyncio.run(run_tests())
    sys.exit(exit_code)

if __name__ == "__main__":
    main()