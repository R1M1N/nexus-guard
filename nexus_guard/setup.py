"""
NEXUS GUARD - Setup and Installation Script
Automated setup for the cybersecurity platform
"""

import os
import sys
import subprocess
import json
import secrets
import string
from pathlib import Path
from typing import Dict, Any

def generate_secure_key(length: int = 32) -> str:
    """Generate a secure random key"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def create_environment_file():
    """Create .env file with secure configuration"""
    env_content = f"""# NEXUS GUARD - Enterprise Cybersecurity Platform Configuration
# Generated automatically - DO NOT commit this file to version control

# Application Settings
DEBUG=false
DEPLOYMENT_MODE=PRODUCTION
SECURITY_LEVEL=HIGH

# Security Keys (Generated for this installation)
API_SECRET_KEY={generate_secure_key(64)}
JWT_SECRET_KEY={generate_secure_key(64)}
ENCRYPTION_KEY={generate_secure_key(32)}

# Database Configuration
DATABASE_URL=postgresql://nexus_user:{generate_secure_key(16)}@localhost:5432/nexus_guard
REDIS_URL=redis://localhost:6379/0
MONGODB_URL=mongodb://localhost:27017/nexus_guard

# AI/ML Configuration
AI_MODEL_PATH=/app/models
FEDERATED_LEARNING_ENABLED=true
PRIVACY_PRESERVATION_LEVEL=HIGH

# Threat Detection Thresholds
ANOMALY_DETECTION_THRESHOLD=0.85
MALWARE_DETECTION_THRESHOLD=0.90
INTRUSION_DETECTION_THRESHOLD=0.95
ZERO_DAY_DETECTION_THRESHOLD=0.75

# Response Configuration
AUTOMATED_RESPONSE_ENABLED=true
AUTO_ISOLATION_THRESHOLD=0.95
HUMAN_VERIFICATION_REQUIRED=true

# Network Monitoring
NETWORK_MONITORING_ENABLED=true
WIRELESS_MONITORING_ENABLED=true
PACKET_CAPTURE_ENABLED=true

# Blockchain Configuration
BLOCKCHAIN_ENABLED=true
BLOCKCHAIN_NETWORK=hyperledger-fabric
AUDIT_LOG_RETENTION_DAYS=2555

# Scalability Settings
MAX_CONCURRENT_CONNECTIONS=10000
WORKER_PROCESSES=4
MODEL_CACHE_SIZE_GB=100

# Compliance Settings
GDPR_COMPLIANCE=true
HIPAA_COMPLIANCE=false
SOX_COMPLIANCE=false
ISO27001_COMPLIANCE=true

# Monitoring & Observability
PROMETHEUS_ENABLED=true
JAEGER_ENABLED=true
LOG_LEVEL=INFO

# External Integrations
SIEM_INTEGRATION_ENABLED=true
THREAT_INTEL_API_KEY=
VIRUS_TOTAL_API_KEY=
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("✅ Created secure .env configuration file")

def check_python_version():
    """Check if Python version is supported"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    
    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], check=True)
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        sys.exit(1)

def create_directories():
    """Create necessary directories"""
    directories = [
        "models",
        "logs",
        "data",
        "certificates",
        "config",
        "scripts"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    print("✅ Created necessary directories")

def setup_database():
    """Setup database initialization scripts"""
    db_init_script = """-- NEXUS GUARD Database Initialization
-- PostgreSQL initialization script

-- Create database (run as superuser)
CREATE DATABASE nexus_guard;

-- Create user
CREATE USER nexus_user WITH ENCRYPTED PASSWORD 'change_this_password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE nexus_guard TO nexus_user;

-- Connect to nexus_guard database
\\c nexus_guard;

-- Create schemas
CREATE SCHEMA IF NOT EXISTS threat_detection;
CREATE SCHEMA IF NOT EXISTS response_management;
CREATE SCHEMA IF NOT EXISTS federated_learning;
CREATE SCHEMA IF NOT EXISTS blockchain_audit;

-- Grant schema privileges
GRANT ALL ON SCHEMA threat_detection TO nexus_user;
GRANT ALL ON SCHEMA response_management TO nexus_user;
GRANT ALL ON SCHEMA federated_learning TO nexus_user;
GRANT ALL ON SCHEMA blockchain_audit TO nexus_user;

-- Create extension for JSON operations
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Grant usage on extensions
GRANT USAGE ON SCHEMA public TO nexus_user;
"""
    
    with open("scripts/init_database.sql", "w") as f:
        f.write(db_init_script)
    
    print("✅ Created database initialization script")

def create_docker_compose():
    """Create Docker Compose configuration"""
    compose_config = {
        "version": "3.8",
        "services": {
            "nexus-guard-api": {
                "build": ".",
                "ports": ["8080:8080"],
                "environment": [
                    "DATABASE_URL=postgresql://nexus_user:password@postgres:5432/nexus_guard",
                    "REDIS_URL=redis://redis:6379/0",
                    "MONGODB_URL=mongodb://mongodb:27017/nexus_guard"
                ],
                "depends_on": ["postgres", "redis", "mongodb"],
                "volumes": ["./models:/app/models", "./logs:/app/logs"],
                "restart": "unless-stopped",
                "networks": ["nexus-network"]
            },
            "postgres": {
                "image": "postgres:15",
                "environment": {
                    "POSTGRES_DB": "nexus_guard",
                    "POSTGRES_USER": "nexus_user",
                    "POSTGRES_PASSWORD": "secure_password_here"
                },
                "volumes": ["postgres_data:/var/lib/postgresql/data"],
                "restart": "unless-stopped",
                "networks": ["nexus-network"]
            },
            "redis": {
                "image": "redis:7-alpine",
                "volumes": ["redis_data:/data"],
                "restart": "unless-stopped",
                "networks": ["nexus-network"]
            },
            "mongodb": {
                "image": "mongodb:7",
                "environment": {
                    "MONGO_INITDB_ROOT_USERNAME": "admin",
                    "MONGO_INITDB_ROOT_PASSWORD": "secure_password_here"
                },
                "volumes": ["mongodb_data:/data/db"],
                "restart": "unless-stopped",
                "networks": ["nexus-network"]
            },
            "prometheus": {
                "image": "prom/prometheus",
                "ports": ["9090:9090"],
                "volumes": ["./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml"],
                "restart": "unless-stopped",
                "networks": ["nexus-network"]
            },
            "grafana": {
                "image": "grafana/grafana",
                "ports": ["3000:3000"],
                "environment": {
                    "GF_SECURITY_ADMIN_PASSWORD": "admin_password_here"
                },
                "volumes": ["grafana_data:/var/lib/grafana"],
                "restart": "unless-stopped",
                "networks": ["nexus-network"]
            }
        },
        "volumes": {
            "postgres_data": {},
            "redis_data": {},
            "mongodb_data": {},
            "grafana_data": {}
        },
        "networks": {
            "nexus-network": {
                "driver": "bridge"
            }
        }
    }
    
    with open("docker-compose.yml", "w") as f:
        json.dump(compose_config, f, indent=2)
    
    print("✅ Created Docker Compose configuration")

def create_dockerfile():
    """Create Dockerfile for the application"""
    dockerfile_content = """# NEXUS GUARD - Multi-stage Dockerfile
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    curl \\
    wget \\
    git \\
    netcat-traditional \\
    nmap \\
    tcpdump \\
    iptables \\
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash nexus

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p models logs data certificates config scripts && \\
    chown -R nexus:nexus /app

# Switch to non-root user
USER nexus

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8080/api/v2/system/health || exit 1

# Run application
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
"""
    
    with open("Dockerfile", "w") as f:
        f.write(dockerfile_content)
    
    print("✅ Created Dockerfile")

def create_monitoring_config():
    """Create monitoring configuration files"""
    # Prometheus configuration
    prometheus_config = {
        "global": {"scrape_interval": "15s"},
        "scrape_configs": [
            {
                "job_name": "nexus-guard",
                "static_configs": [{"targets": ["nexus-guard-api:8080"]}],
                "metrics_path": "/metrics",
                "scrape_interval": "5s"
            }
        ]
    }
    
    os.makedirs("monitoring", exist_ok=True)
    with open("monitoring/prometheus.yml", "w") as f:
        json.dump(prometheus_config, f, indent=2)
    
    print("✅ Created monitoring configuration")

def create_startup_scripts():
    """Create startup and management scripts"""
    
    # Start script
    start_script = """#!/bin/bash
# NEXUS GUARD Startup Script

echo "🚀 Starting NEXUS GUARD Cybersecurity Platform..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ .env file not found. Please run setup.py first."
    exit 1
fi

# Load environment variables
source .env

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Start services
echo "📦 Starting services with Docker Compose..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check health
echo "🔍 Checking system health..."
curl -f http://localhost:8080/api/v2/system/health

echo "✅ NEXUS GUARD Platform is running!"
echo "📊 Dashboard: http://localhost:8080/docs"
echo "📈 Monitoring: http://localhost:3000 (admin/admin)"
"""
    
    with open("start.sh", "w") as f:
        f.write(start_script)
    os.chmod("start.sh", 0o755)
    
    # Stop script
    stop_script = """#!/bin/bash
# NEXUS GUARD Stop Script

echo "🛑 Stopping NEXUS GUARD Cybersecurity Platform..."

docker-compose down

echo "✅ NEXUS GUARD Platform stopped"
"""
    
    with open("stop.sh", "w") as f:
        f.write(stop_script)
    os.chmod("stop.sh", 0o755)
    
    print("✅ Created startup scripts")

def create_monitoring_script():
    """Create system monitoring script"""
    monitor_script = """#!/usr/bin/env python3
# NEXUS GUARD System Monitoring Script

import requests
import json
import time
from datetime import datetime

def check_system_health():
    \"\"\"Check system health and performance\"\"\"
    try:
        response = requests.get("http://localhost:8080/api/v2/system/health", timeout=10)
        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ System Health: {health_data['status']}")
            print(f"📊 Components: {json.dumps(health_data['components'], indent=2)}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def check_dashboard():
    \"\"\"Check dashboard analytics\"\"\"
    try:
        response = requests.get("http://localhost:8080/api/v2/analytics/dashboard", timeout=10)
        if response.status_code == 200:
            dashboard_data = response.json()
            print(f"🛡️  Current Threat Level: {dashboard_data['threat_level']}")
            print(f"🔍 Total Detections: {dashboard_data['total_detections']}")
            print(f"⚡ Active Responses: {dashboard_data['active_responses']}")
            return True
        else:
            print(f"❌ Dashboard check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Dashboard check error: {e}")
        return False

if __name__ == "__main__":
    print("🔍 NEXUS GUARD System Monitoring")
    print("=" * 50)
    
    while True:
        print(f"\\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if check_system_health():
            check_dashboard()
        else:
            print("❌ System appears to be down!")
        
        time.sleep(60)  # Check every minute
"""
    
    with open("monitor.py", "w") as f:
        f.write(monitor_script)
    os.chmod("monitor.py", 0o755)
    
    print("✅ Created monitoring script")

def create_security_hardening():
    """Create security hardening configuration"""
    security_config = """# NEXUS GUARD Security Hardening Configuration

# 1. Firewall Rules (iptables)
*filter
# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow loopback
-A INPUT -i lo -j ACCEPT
# Allow SSH (restrict to specific IPs in production)
-A INPUT -p tcp --dport 22 -j ACCEPT
# Allow NEXUS GUARD API
-A INPUT -p tcp --dport 8080 -j ACCEPT
# Allow monitoring
-A INPUT -p tcp --dport 3000 -j ACCEPT  # Grafana
-A INPUT -p tcp --dport 9090 -j ACCEPT  # Prometheus
# Drop all other input
-A INPUT -j DROP
# Allow all output
-A OUTPUT -j ACCEPT
COMMIT

# 2. System Security Settings
# Enable automatic security updates
echo "Unattended-Upgrades::Automatic-Reboot-Time \"02:00\";" >> /etc/apt/apt.conf.d/50unattended-upgrades

# 3. SSL/TLS Configuration
# Use strong cipher suites
ssl_protocols = TLSv1.2 TLSv1.3
ssl_ciphers = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305
ssl_prefer_server_ciphers = on

# 4. Rate Limiting
# Apply rate limits to API endpoints
location /api/v2/threats/ {
    limit_req zone=api burst=10 nodelay;
    proxy_pass http://nexus-guard-api;
}

# 5. Security Headers
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
add_header Content-Security-Policy "default-src 'self'";
"""
    
    os.makedirs("security", exist_ok=True)
    with open("security/hardening.conf", "w") as f:
        f.write(security_config)
    
    print("✅ Created security hardening configuration")

def validate_installation():
    """Validate the installation"""
    print("🔍 Validating installation...")
    
    checks = [
        ("Environment file", ".env"),
        ("Docker Compose", "docker-compose.yml"),
        ("Dockerfile", "Dockerfile"),
        ("Database script", "scripts/init_database.sql"),
        ("Monitoring config", "monitoring/prometheus.yml"),
        ("Startup scripts", "start.sh"),
        ("Monitoring script", "monitor.py"),
        ("Security config", "security/hardening.conf")
    ]
    
    all_valid = True
    for name, path in checks:
        if os.path.exists(path):
            print(f"✅ {name}: Found")
        else:
            print(f"❌ {name}: Missing")
            all_valid = False
    
    if all_valid:
        print("\n🎉 Installation validation passed!")
        print("\n📋 Next Steps:")
        print("1. Review and update .env configuration")
        print("2. Start the platform: ./start.sh")
        print("3. Monitor the system: python monitor.py")
        print("4. Access the dashboard: http://localhost:8080/docs")
        print("5. View monitoring: http://localhost:3000")
        return True
    else:
        print("\n❌ Installation validation failed!")
        return False

def main():
    """Main setup function"""
    print("🛡️  NEXUS GUARD - Enterprise Cybersecurity Platform Setup")
    print("=" * 60)
    
    # Check Python version
    check_python_version()
    
    # Create environment configuration
    create_environment_file()
    
    # Install dependencies
    install_dependencies()
    
    # Create directory structure
    create_directories()
    
    # Setup database
    setup_database()
    
    # Create Docker configuration
    create_docker_compose()
    create_dockerfile()
    
    # Create monitoring setup
    create_monitoring_config()
    
    # Create management scripts
    create_startup_scripts()
    create_monitoring_script()
    
    # Create security hardening
    create_security_hardening()
    
    # Validate installation
    if validate_installation():
        print("\n✨ NEXUS GUARD setup completed successfully!")
        print("\n⚠️  SECURITY REMINDER:")
        print("- Change default passwords in docker-compose.yml")
        print("- Update API keys in .env file")
        print("- Configure firewall rules")
        print("- Review security hardening configuration")
    else:
        print("\n❌ Setup completed with errors")
        sys.exit(1)

if __name__ == "__main__":
    main()